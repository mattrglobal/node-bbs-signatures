#[macro_use]
mod macros;

use neon::prelude::*;
use neon::register_module;
use neon::result::Throw;
use std::collections::{BTreeMap, BTreeSet};
use zmix::amcl_wrapper::{
    group_elem::{GroupElement, GroupElementVector},
    group_elem_g1::G1Vector,
};
use zmix::signatures::bbs::prelude::*;
use zmix::signatures::{SignatureBlinding, SignatureMessage, SignatureMessageVector};

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_key(mut cx: FunctionContext) -> JsResult<JsObject> {
    let seed = match cx.argument_opt(0) {
        Some(arg) => {
            let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let seed_data = cx.borrow(&arg, |data| data.as_slice::<u8>());
            Some(KeyGenOption::UseSeed(seed_data.to_vec()))
        }
        None => None,
    };

    let (pk, sk) = DeterministicPublicKey::new(seed);

    let pk_array = slice_to_js_array_buffer!(pk.to_bytes().as_slice(), cx);
    let sk_array = slice_to_js_array_buffer!(sk.to_bytes().as_slice(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "publicKey", pk_array)?;
    result.set(&mut cx, "secretKey", sk_array)?;

    Ok(result)
}

/// Generate a BBS+ signature
/// The first argument is the domain separation label
/// The second argument is the private key `x` created from bls_generate_key.
/// The remaining values are the messages to be signed.
/// If no messages are supplied, an error is thrown.
///
/// `signature_context`: `Object` the context for the signature creation
/// The context object model is as follows:
/// {
///     "secretKey": ArrayBuffer                 // The private key of signer
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages to be signed as ArrayBuffers
///     "dst": ArrayBuffer                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `ArrayBuffer` the signature
fn bbs_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let sk = SecretKey::from_bytes(&obj_field_to_slice!(&mut cx, js_obj, "secretKey")).map_err(|_| Throw)?;
    let (pk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(&mut cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = SignatureMessage::from_bytes(&cast_to_slice!(&mut cx, message_bytes[i])).map_err(|_| Throw)?;
        messages.push(message);
    }
    let pk = pk.to_public_key(messages.len(), dst);

    let signature = Signature::new(messages.as_slice(), &sk, &pk).map_err(|_| Throw)?;
    let result = slice_to_js_array_buffer!(signature.to_bytes().as_slice(), cx);
    Ok(result)
}

/// Verify a BBS+ signature
/// The first argument is the domain separation label
/// The second argument is the public key `w` created from bls_generate_key
/// The third argument is the signature to be verified.
/// The remaining values are the messages that were signed
///
/// `signature_context`: `Object` the context for verifying the signature
/// {
///     "publicKey": ArrayBuffer                // The public key
///     "signature": ArrayBuffer                // The signature
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that were signed as ArrayBuffers
///     "dst": ArrayBuffer                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: true if valid `signature` on `messages`
fn bbs_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let w = DeterministicPublicKey::from_bytes(&obj_field_to_slice!(&mut cx, js_obj, "publicKey")).map_err(|_| Throw)?;
    let signature = Signature::from_bytes(&obj_field_to_slice!(&mut cx, js_obj, "signature")).map_err(|_| Throw)?;
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(&mut cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = SignatureMessage::from_bytes(&cast_to_slice!(&mut cx, message_bytes[i])).map_err(|_| Throw)?;
        messages.push(message);
    }

    let pk = w.to_public_key(messages.len(), dst);

    match signature.verify(messages.as_slice(), &pk) {
        Ok(b) => Ok(cx.boolean(b)),
        Err(_) => Err(Throw),
    }
}

/// This method should be called by the signature recipient and not the signer.
///
/// Creates the commitment and proof to be used in a blinded signature.
/// First, caller's should extract the blinding factor and use this to unblind
/// the signature once the other party has generated the signature. Everything
/// else should be sent to the signer. The signer needs the commitment to finish
/// the signature and the proof of knowledge of committed values. The blinding
/// requires the public key and the message indices to be blinded.
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "publicKey": ArrayBuffer                // The public key of signer
///     "messageCount": Number                  // The total number of messages that will be signed––both hidden and known.
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that will be blinded as ArrayBuffers
///     "hidden": [0, 1],                       // The zero based indices to the generators in the public key for the messages.
///     "sessionId": ArrayBuffer                // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": ArrayBuffer                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `Object` with the following fields
/// {
///     "commitment": ArrayBuffer,
///     "proofOfHiddenMessages": ArrayBuffer,
///     "challengeHash": ArrayBuffer,
///     "blindingFactor": ArrayBuffer
/// }
///
/// The caller must make sure that "blinding_factor" is not passed to the signer. This
/// would allow the issuer to unblind the signature but would still not know the hidden message
/// values.
fn bbs_blind_signature_commitment(mut cx: FunctionContext) -> JsResult<JsObject> {
    let bcx = extract_blinding_context(&mut cx)?;
    let bcx = generate_blind_values(bcx);
    get_blind_commitment(cx, bcx)
}

fn get_blind_commitment(mut cx: FunctionContext, bcx: BlindedContext) -> JsResult<JsObject> {
    let commitment = slice_to_js_array_buffer!(bcx.commitment.to_bytes().as_slice(), cx);
    let challenge_hash = slice_to_js_array_buffer!(bcx.challenge_hash.to_bytes().as_slice(), cx);
    let blinding_factor = slice_to_js_array_buffer!(bcx.blinding_factor.to_bytes().as_slice(), cx);
    let proof = slice_to_js_array_buffer!(bcx.proof.to_bytes().as_slice(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "commitment", commitment)?;
    result.set(&mut cx, "challengeHash", challenge_hash)?;
    result.set(&mut cx, "blindingFactor", blinding_factor)?;
    result.set(&mut cx, "proofOfHiddenMessages", proof)?;
    Ok(result)
}

fn generate_blind_values(bcx: BlindingContext) -> BlindedContext {
    let pk = bcx
        .public_key
        .to_public_key(bcx.message_count, bcx.dst.clone());

    let blinding_factor = Signature::generate_blinding();

    let mut points = G1Vector::with_capacity(bcx.messages.len() + 1);
    let mut scalars = SignatureMessageVector::with_capacity(bcx.messages.len() + 1);
    // h0^blinding_factor*hi^mi.....
    points.push(pk.h0.clone());
    scalars.push(blinding_factor.clone());
    let mut committing = ProverCommittingG1::new();
    committing.commit(&pk.h0, None);

    for (i, m) in &bcx.messages {
        points.push(pk.h[*i].clone());
        scalars.push(m.clone());
        committing.commit(&pk.h[*i], None);
    }

    //User creates a random commitment, computes challenges and response. The proof of knowledge consists of a commitment and responses
    //User and signer engage in a proof of knowledge for `commitment`
    let commitment = points
        .multi_scalar_mul_const_time(scalars.as_slice())
        .unwrap();
    let committed = committing.finish();

    let mut extra = Vec::new();
    extra.extend_from_slice(commitment.to_bytes().as_slice());
    if let Some(b) = bcx.session_id {
        extra.extend_from_slice(b.as_slice());
    }
    let challenge_hash = committed.gen_challenge(extra);
    let proof = committed
        .gen_proof(&challenge_hash, scalars.as_slice())
        .unwrap();

    BlindedContext {
        blinding_factor,
        challenge_hash,
        commitment,
        proof,
    }
}

fn extract_blinding_context(cx: &mut FunctionContext) -> Result<BlindingContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = js_obj
        .get(cx, "messageCount")?
        .downcast::<JsNumber>()
        .unwrap_or(cx.number(-1))
        .value();

    if message_count < 0f64 {
        return Err(Throw);
    }

    let public_key = DeterministicPublicKey::from_bytes(&obj_field_to_slice!(cx, js_obj, "publicKey")).map_err(|_| Throw)?;
    let session_id = obj_field_to_opt_bytes!(cx, js_obj, "sessionId");
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;

    let hidden = obj_field_to_vec!(cx, js_obj, "hidden");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    if hidden.len() != message_bytes.len() {
        return Err(Throw);
    }

    let mut messages = BTreeMap::new();

    for i in 0..hidden.len() {
        let index = hidden[i]
            .downcast::<JsNumber>()
            .unwrap_or(cx.number(-1))
            .value();

        if index < 0f64 || index > message_count {
            return Err(Throw);
        }
        let message = SignatureMessage::from_bytes(&cast_to_slice!(cx, message_bytes[i])).map_err(|_| Throw)?;

        messages.insert(index as usize, message);
    }
    let message_count = message_count as usize;

    Ok(BlindingContext {
        public_key,
        message_count,
        messages,
        session_id,
        dst,
    })
}

struct BlindedContext {
    blinding_factor: SignatureBlinding,
    challenge_hash: SignatureMessage,
    commitment: BlindedSignatureCommitment,
    proof: ProofG1,
}

struct BlindingContext {
    public_key: DeterministicPublicKey,
    message_count: usize,
    messages: BTreeMap<usize, SignatureMessage>,
    session_id: Option<Vec<u8>>,
    dst: DomainSeparationTag,
}

/// Generate a BBS+ blind signature.
/// This should be called by the signer and not the signature recipient
/// 1 or more messages have been hidden by the signature recipient.
/// The hidden and known messages are signed. This also verifies a
/// proof of committed messages sent by the signature recipient.
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "commitment": ArrayBuffer                // The commitment received from the intended recipient
///     "proofOfHiddenMessages": ArrayBuffer     // The proof of hidden messages from the intended recipient
///     "challengeHash": ArrayBuffer             // The challenge hash from the intended recipient
///     "secretKey": ArrayBuffer                 // The secret key used for generating the signature
///     "messageCount": Number                   // The total number of messages that will be signed––both hidden and known.
///     "messages": [ArrayBuffer, ArrayBuffer]   // The messages that will be signed as ArrayBuffers
///     "known": [2, 3, 4],                      // The zero based indices to the generators in the public key for the messages.
///     "sessionId": ArrayBuffer                 // This is the optional nonce sent from the signer used in the proof of hidden messages
///     "dst": ArrayBuffer                       // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `ArrayBuffer` the blinded signature. Recipient must unblind before it is valid
fn bbs_blind_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let bcx = extract_blind_signature_context(&mut cx)?;
    let signature = sign_blind(bcx)?;

    let result = slice_to_js_array_buffer!(signature.to_bytes().as_slice(), cx);
    Ok(result)
}

fn sign_blind(bcx: BlindSignatureContext) -> Result<Signature, Throw> {
    let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(bcx.secret_key.clone())));

    let pk = dpk.to_public_key(bcx.message_count, bcx.dst.clone());

    // Verify the proof
    // First get the generators used to create the commitment
    let mut bases = Vec::new();
    bases.push(pk.h0.clone());
    for i in 0..bcx.message_count {
        if !bcx.messages.contains_key(&i) {
            bases.push(pk.h[i].clone());
        }
    }

    // Include the nonce if it exists
    let mut nonce = Vec::new();
    if let Some(n) = bcx.session_id {
        nonce = n;
    }
    // Verify proof of hidden messages
    if !bcx.proof.verify_complete_proof(bases.as_slice(), &bcx.commitment, &bcx.challenge_hash, nonce.as_slice()).map_err(|_| Throw)? {
        return Err(Throw);
    }

    Ok(Signature::new_blind(&bcx.commitment, &bcx.messages, &bcx.secret_key, &pk).map_err(|_| Throw)?)
}

fn extract_blind_signature_context(cx: &mut FunctionContext) -> Result<BlindSignatureContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = js_obj
        .get(cx, "messageCount")?
        .downcast::<JsNumber>()
        .unwrap_or(cx.number(-1))
        .value();

    if message_count < 0f64 {
        return Err(Throw);
    }

    let secret_key = SecretKey::from_bytes(&obj_field_to_slice!(cx, js_obj, "secretKey")).map_err(|_| Throw)?;
    let session_id = obj_field_to_opt_bytes!(cx, js_obj, "sessionId");
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;
    let known = obj_field_to_vec!(cx, js_obj, "known");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    if known.len() != message_bytes.len() {
        return Err(Throw);
    }

    let mut messages = BTreeMap::new();

    for i in 0..known.len() {
        let index = known[i]
            .downcast::<JsNumber>()
            .unwrap_or(cx.number(-1))
            .value();

        if index < 0f64 || index > message_count {
            return Err(Throw);
        }
        let message = SignatureMessage::from_bytes(&cast_to_slice!(cx, message_bytes[i])).map_err(|_| Throw)?;

        messages.insert(index as usize, message);
    }

    let commitment = BlindedSignatureCommitment::from_bytes(&obj_field_to_slice!(cx, js_obj, "commitment")).map_err(|_| Throw)?;
    let challenge_hash = SignatureMessage::from_bytes(&obj_field_to_slice!(cx, js_obj, "challengeHash")).map_err(|_| Throw)?;
    let proof = ProofG1::from_bytes(&obj_field_to_slice!(cx, js_obj, "proofOfHiddenMessages")).map_err(|_| Throw)?;

    let message_count = message_count as usize;

    Ok(BlindSignatureContext {
        challenge_hash,
        commitment,
        dst,
        message_count,
        messages,
        proof,
        secret_key,
        session_id,
    })
}

struct BlindSignatureContext {
    challenge_hash: SignatureMessage,
    commitment: BlindedSignatureCommitment,
    dst: DomainSeparationTag,
    message_count: usize,
    messages: BTreeMap<usize, SignatureMessage>,
    proof: ProofG1,
    /// This is automatically zeroed on drop
    secret_key: SecretKey,
    session_id: Option<Vec<u8>>,
}

/// Takes a blinded signature and makes it unblinded
///
/// inputs are the signature and the blinding factor generated from
/// `bbs_blind_signature_commitment`
///
/// `signature`: `ArrayBuffer` length must be `SIGNATURE_SIZE`
/// `blindingFactor`: `ArrayBuffer` length must be `MESSAGE_SIZE`
/// `return`: `ArrayBuffer` the unblinded signature
fn bbs_get_unblinded_signature(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(0)?;
    let sig = cx.borrow(&arg, |d| d.as_slice::<u8>());

    let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(1)?;
    let bf = cx.borrow(&arg, |d| d.as_slice::<u8>());

    let sig = Signature::from_bytes(sig).map_err(|_| Throw)?;
    let bf = SignatureBlinding::from_bytes(bf).map_err(|_| Throw)?;

    let sig = sig.get_unblinded_signature(&bf);

    let signature_bytes = sig.to_bytes();
    let mut result = JsArrayBuffer::new(&mut cx, signature_bytes.len() as u32)?;

    cx.borrow_mut(&mut result, |slice| {
        let bytes = slice.as_mut_slice::<u8>();
        for i in 0..signature_bytes.len() {
            bytes[i] = signature_bytes[i];
        }
    });
    Ok(result)
}

/// Create a signature proof of knowledge. This includes revealing some messages
/// and retaining others. Not revealed attributes will have a proof of committed values
/// instead of revealing the values.
///
/// `create_proof_context`: `Object` the context for creating a proof
/// The context object model is as follows:
/// {
///     "signature": ArrayBuffer,               // The signature to be proved
///     "publicKey": ArrayBuffer,               // The public key of the signer
///     "messages": [ArrayBuffer, ArrayBuffer]  // All messages that were signed in the order they correspond to the generators in the public key.
///     "revealed": [2, 3]                      // The zero based indices to the generators in the public key for the messages to be revealed. All other messages will be hidden from the verifier.
///     "sessionId": ArrayBuffer                // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": ArrayBuffer                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `ArrayBuffer` the proof to send to the verifier
fn bbs_create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let pcx = extract_create_proof_context(&mut cx)?;
    let proof = generate_proof(pcx)?;
    Ok(slice_to_js_array_buffer!(proof.to_bytes().as_slice(), cx))
}

fn generate_proof(pcx: CreateProofContext) -> Result<PoKOfSignatureProof, Throw> {
    let pk = pcx.public_key.to_public_key(pcx.messages.len(), pcx.dst);

    let pok = PoKOfSignature::init(&pcx.signature, &pk, pcx.messages.as_slice(), None, pcx.revealed.clone()).map_err(|_| Throw)?;
    let mut challenge_bytes = pok.to_bytes();
    if let Some(b) = pcx.session_id {
        challenge_bytes.extend_from_slice(b.as_slice());
    }

    let challenge_hash = SignatureMessage::from_msg_hash(&challenge_bytes);
    Ok(pok.gen_proof(&challenge_hash).map_err(|_| Throw)?)
}

fn extract_create_proof_context(cx: &mut FunctionContext) -> Result<CreateProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = Signature::from_bytes(&obj_field_to_slice!(cx, js_obj, "signature")).map_err(|_| Throw)?;
    let public_key = DeterministicPublicKey::from_bytes(&obj_field_to_slice!(cx, js_obj, "publicKey")).map_err(|_| Throw)?;
    let session_id = obj_field_to_opt_bytes!(cx, js_obj, "sessionId");
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;
    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = SignatureMessage::from_bytes(&cast_to_slice!(cx, message_bytes[i])).map_err(|_| Throw)?;
        messages.push(message);
    }

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = revealed_indices[i]
            .downcast::<JsNumber>()
            .unwrap_or(cx.number(-1))
            .value();

        if index < 0f64 || index as usize > messages.len() {
            return Err(Throw);
        }
        revealed.insert(index as usize);
    }

    Ok(CreateProofContext {
        signature,
        public_key,
        messages,
        revealed,
        session_id,
        dst
    })
}

struct CreateProofContext {
    signature: Signature,
    public_key: DeterministicPublicKey,
    messages: Vec<SignatureMessage>,
    revealed: BTreeSet<usize>,
    session_id: Option<Vec<u8>>,
    dst: DomainSeparationTag
}

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer
///     "messageCount": Number                  // The total number of messages that were included in the signature
///     "messages": [ArrayBuffer, ArrayBuffer]  // The revealed messages.
///     "revealed": [2, 3]                      // The zero based indices to the generators in the public key for the messages to be revealed.
///     "sessionId": ArrayBuffer                // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": ArrayBuffer                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: true if valid
fn bbs_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let vcx = extract_verify_proof_context(&mut cx)?;

    match verify_proof(vcx) {
        Ok(b) => Ok(cx.boolean(b)),
        Err(_) => Err(Throw),
    }
}

fn verify_proof(vcx: VerifyProofContext) -> Result<bool, Throw> {
    let pk = vcx.public_key.to_public_key(vcx.message_count, vcx.dst.clone());
    let mut revealed_msgs = BTreeMap::new();
    for i in &vcx.revealed {
        revealed_msgs.insert(i.clone(), vcx.messages[*i].clone());
    }
    // The verifier generates the challenge on its own.
    let mut challenge_bytes = vcx.proof.get_bytes_for_challenge(vcx.revealed.clone(), &pk);

    if let Some(b) = vcx.session_id {
        challenge_bytes.extend_from_slice(b.as_slice());
    }
    let challenge_verifier = SignatureMessage::from_msg_hash(&challenge_bytes);
    Ok(vcx.proof.verify(&pk, revealed_msgs.clone(), &challenge_verifier).map_err(|_| Throw)?)
}

fn extract_verify_proof_context(cx: &mut FunctionContext) -> Result<VerifyProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = js_obj
        .get(cx, "messageCount")?
        .downcast::<JsNumber>()
        .unwrap_or(cx.number(-1))
        .value();

    if message_count < 0f64 {
        return Err(Throw);
    }

    let proof = PoKOfSignatureProof::from_bytes(&obj_field_to_slice!(cx, js_obj, "proof")).map_err(|_| Throw)?;
    let public_key = DeterministicPublicKey::from_bytes(&obj_field_to_slice!(cx, js_obj, "publicKey")).map_err(|_| Throw)?;
    let session_id = obj_field_to_opt_bytes!(cx, js_obj, "sessionId");
    let dst = DomainSeparationTag::new(&obj_field_to_slice!(cx, js_obj, "dst"), None, None, None).map_err(|_| Throw)?;
    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = SignatureMessage::from_bytes(&cast_to_slice!(cx, message_bytes[i])).map_err(|_| Throw)?;
        messages.push(message);
    }

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = revealed_indices[i]
            .downcast::<JsNumber>()
            .unwrap_or(cx.number(-1))
            .value();

        if index < 0f64 || index > message_count {
            return Err(Throw);
        }
        revealed.insert(index as usize);
    }

    let message_count = message_count as usize;

    Ok(VerifyProofContext {
        proof,
        public_key,
        messages,
        message_count,
        revealed,
        session_id,
        dst
    })
}

struct VerifyProofContext {
    dst: DomainSeparationTag,
    messages: Vec<SignatureMessage>,
    message_count: usize,
    proof: PoKOfSignatureProof,
    public_key: DeterministicPublicKey,
    revealed: BTreeSet<usize>,
    session_id: Option<Vec<u8>>,
}

/// Computes `u` = `generator`^`value`
/// `generator` is expected to be in G1 and `value` is handled in Fp
///
/// `generator`: `ArrayBuffer` length must be `COMMITMENT_SIZE`
/// `value`: `ArrayBuffer` length must be `MESSAGE_SIZE`
/// `return`: `ArrayBuffer`
fn bls_commitment(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    unimplemented!();
    //     let generator: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(0)?;
    //     let value: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(1)?;
    //
    //     let base = cx.borrow(&generator, |data| { data.as_slice::<u8>() });
    //
    //     if base.len() != COMMITMENT_SIZE {
    //         return Err(Throw);
    //     }
    //
    //     let exponent = cx.borrow(&value, |data| { data.as_slice::<u8>() });
    //
    //     if exponent.len() != MESSAGE_SIZE {
    //         return Err(Throw);
    //     }
    //
    //     let g = G1::from_bytes(base).map_err(|_| Throw)?;
    //     let e = amcl_wrapper::field_elem::FieldElement::from_bytes(exponent).map_err(|_| Throw)?;
    //     let res = g.scalar_mul_const_time(&e);
    //
    //     let mut commitment = JsArrayBuffer::new(&mut cx, SECRET_KEY_SIZE as u32)?;
    //     cx.borrow_mut(&mut commitment, |slice| {
    //         let bytes = slice.as_mut_slice::<u8>();
    //         bytes.copy_from_slice(res.to_bytes().as_slice());
    //     });
    //     Ok(commitment)
}

/// Create a generator in G1
/// `seed`: `ArrayBuffer` [opt]
///
/// `return`: `ArrayBuffer`
// fn bls_create_generator_g1(mut cx: FunctionContent) -> JsResult<JsArrayBuffer> {
//     let seed =
//         match cx.argument_opt(0) {
//             Some(arg) => {
//                 let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
//                 let seed_data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
//                 Some(KeyGenOption::UseSeed(seed_data.to_vec()))
//             },
//             None => G1::generator()
//         };
//
//
// }

// declare_types! {
//   pub class JsBlsKeyPair for BlsKeyPair {
//     init(mut cx) {
//
//       let seed = match cx.argument_opt(0) {
//         Some(arg) => {
//             let seed_type: Handle<JsString> = arg.downcast::<Js>
//             let bytes: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(1)?;
//             match arg {
//                 "seed" => {
//                 },
//                 "key" => {
//
//                 },
//                 _ => None
//             }
//         },
//         None => None
//       };

// let seed =
//   match cx.argument_opt(1) {
//       Some(arg) => {
//           let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
//           let seed_data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
//           Some(KeyGenOption::UseSeed(seed_data.to_vec()))
//       },
//       None => None
//   };

// let (pk, sk) = DeterministicPublicKey::new(seed);
//
// Ok(BlsKeyPair { pk, sk: Some(sk) })
// }
//
// method fromPrivateKey(mut cx) {
//     let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(0)?;
//
//     let sk = cx.borrow(&arg, |data| { data.as_slice::<u8>() } );
//
//     if sk.len() != SECRET_KEY_SIZE {
//         return Err(Throw);
//     }
//
//     let (pk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(RawPrivateKey(sk.to_vec()))));
//
//     Ok(BlsKeyPair { pk, sk: Some(sk) })
// }
//
// method publicKey(mut cx) {
//     let this = cx.this();
//
//     let pk = {
//         let guard = cx.lock();
//         let keypair = this.borrow(&guard);
//         keypair.pk.to_bytes()
//     };
//     let mut js_array = JsArrayBuffer::new(&mut cx, pk.len() as u32)?;
//     cx.borrow_mut(&mut js_array, |slice| {
//         let bytes = slice.as_mut_slice::<u8>();
//         for i in 0..pk.len() {
//             bytes[i] = pk[i];
//         }
//     });
//     Ok(js_array.upcast())
// }

// method secretKey(mut cx) {
//     let this = cx.this();
//
//     let sk = {
//         let guard = cx.lock();
//         let keypair = this.borrow(&guard);
//         keypair.sk
//     };
//     match sk {
//         Some(k) => {
//             let data = k.to_bytes();
//             let mut js_array = JsArrayBuffer::new(&mut cx, data.len() as u32)?;
//             cx.borrow_mut(&mut js_array, |slice| {
//                 let bytes = slice.as_mut_slice::<u8>();
//                 for i in 0..data.len() {
//                     bytes[i] = data[i];
//                 }
//             });
//             Ok(js_array.upcast())
//         },
//         None => {
//             Ok(cx.empty_array().upcast())
//         }
//     }
// }

// method bbs_sign(mut cx) {
// let args_length = cx.len();
//
// let messages = Vec::with_capacity(args_length as usize);
// for i in 0..args_length {
//     let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(i)?;
//     let data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
//
//     let m = SignatureMessage::from_bytes(data)?;
//     messages.push(m);
// }
//
// let this = cx.this();
// let sk = {
//     let guard = cx.lock();
//     let keypair = this.borrow(&guard);
//     keypair.sk.to_bytes()
// };
// Ok(())
// }

// method panic(_) {
//   panic!("BbsKeyPair.prototype.panic")
// }
// }
// }

register_module!(mut m, {
    m.export_function("bls_generate_key", bls_generate_key)?;
    m.export_function("bbs_sign", bbs_sign)?;
    m.export_function("bbs_verify", bbs_verify)?;
    m.export_function("bbs_commitment", bls_commitment)?;
    m.export_function("bbs_blind_signature_commitment", bbs_blind_signature_commitment)?;
    m.export_function("bbs_blind_sign", bbs_blind_sign)?;
    m.export_function("bbs_get_unblinded_signature", bbs_get_unblinded_signature)?;
    m.export_function("bbs_create_proof", bbs_create_proof)?;
    m.export_function("bbs_verify_proof", bbs_verify_proof)?;
    // m.export_class::<JsBlsKeyPair>("BbsKeyPair")?;
    Ok(())
});
