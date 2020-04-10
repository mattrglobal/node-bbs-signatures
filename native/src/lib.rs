#[macro_use]
mod macros;

use neon::prelude::*;
use neon::register_module;
use neon::result::Throw;
use std::collections::{BTreeMap, BTreeSet};
use bbs::prelude::*;

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
///     "secretKey": ArrayBuffer           // The private key of signer
///     "messages": [String, String],      // The messages to be signed as strings. They will be hashed with SHAKE-128
///     "dst": String                      // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `ArrayBuffer` the signature
fn bbs_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let sk = handle_err!(SecretKey::from_bytes(&obj_field_to_slice!(&mut cx, js_obj, "secretKey")));
    let (pk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
    let t = obj_field_to_string!(&mut cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(&mut cx, message_bytes[i]);
        messages.push(message);
    }
    let pk = pk.to_public_key(messages.len(), dst);

    let signature = handle_err!(Signature::new(messages.as_slice(), &sk, &pk));
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
///     "messages": [String, String],           // The messages that were signed as strings. They will be SHAKE-256 hashed
///     "dst": String                           // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: true if valid `signature` on `messages`
fn bbs_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let w = DeterministicPublicKey::from_bytes(GenericArray::clone_from_slice(&obj_field_to_slice!(&mut cx, js_obj, "publicKey")));
    let signature = handle_err!(Signature::from_bytes(&obj_field_to_slice!(&mut cx, js_obj, "signature")));
    let t = obj_field_to_string!(&mut cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(&mut cx, message_bytes[i]);
        messages.push(message);
    }

    let pk = w.to_public_key(messages.len(), dst);

    match signature.verify(messages.as_slice(), &pk) {
        Ok(b) => Ok(cx.boolean(b)),
        Err(_) => Ok(cx.boolean(false))
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
///     "messages": [String, String],           // The messages that will be blinded as strings. They will be SHAKE-256 hashed
///     "hidden": [Number, Number],             // The zero based indices to the generators in the public key for the messages.
///     "nonce": String                         // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": String                           // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
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

    let mut points = SignaturePointVector::with_capacity(bcx.messages.len() + 1);
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
    if let Some(b) = bcx.nonce {
        extra.extend_from_slice(b.as_bytes());
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

    let message_count = get_message_count!(cx, js_obj, "messageCount");
    let public_key = DeterministicPublicKey::from_bytes(GenericArray::clone_from_slice(&obj_field_to_slice!(cx, js_obj, "publicKey")));
    let nonce = obj_field_to_opt_string!(cx, js_obj, "nonce");
    let t = obj_field_to_string!(cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));

    let hidden = obj_field_to_vec!(cx, js_obj, "hidden");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    if hidden.len() != message_bytes.len() {
        panic!("hidden length is not the same as messages: {} != {}", hidden.len(), message_bytes.len());
    }

    let mut messages = BTreeMap::new();

    for i in 0..hidden.len() {
        let index = cast_to_number!(cx, hidden[i]);
        if index < 0f64 || index > message_count {
            panic!("Index is out of bounds. Must be between 0 and {}: {}", message_count, index);
        }
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.insert(index as usize, message);
    }
    let message_count = message_count as usize;

    Ok(BlindingContext {
        public_key,
        message_count,
        messages,
        nonce,
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
    nonce: Option<String>,
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
///     "secretKey": ArrayBuffer                 // The secret key used for generating the signature
///     "messageCount": Number                   // The total number of messages that will be signed––both hidden and known.
///     "messages": [String, String]             // The messages that will be signed as strings. They will be hashed with SHAKE-128
///     "dst": String                            // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: `ArrayBuffer` the blinded signature. Recipient must unblind before it is valid
fn bbs_blind_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let bcx = extract_blind_signature_context(&mut cx)?;
    let signature = sign_blind(bcx)?;

    let result = slice_to_js_array_buffer!(signature.to_bytes().as_slice(), cx);
    Ok(result)
}

fn sign_blind(bcx: BlindSignatureContext) -> Result<BlindSignature, Throw> {
    let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(bcx.secret_key.clone())));

    let pk = dpk.to_public_key(bcx.message_count, bcx.dst.clone());

    Ok(handle_err!(BlindSignature::new(&bcx.commitment, &bcx.messages, &bcx.secret_key, &pk)))
}

fn extract_blind_signature_context(cx: &mut FunctionContext) -> Result<BlindSignatureContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = get_message_count!(cx, js_obj, "messageCount");
    let secret_key = handle_err!(SecretKey::from_bytes(&obj_field_to_slice!(cx, js_obj, "secretKey")));
    let t = obj_field_to_string!(cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = BTreeMap::new();

    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.insert(i, message);
    }
    
    let commitment = handle_err!(BlindedSignatureCommitment::from_bytes(&obj_field_to_slice!(cx, js_obj, "commitment")));
   
    let message_count = message_count as usize;

    Ok(BlindSignatureContext {
        commitment,
        dst,
        message_count,
        messages,
        secret_key,
    })
}

struct BlindSignatureContext {
    commitment: BlindedSignatureCommitment,
    dst: DomainSeparationTag,
    message_count: usize,
    messages: BTreeMap<usize, SignatureMessage>,
    /// This is automatically zeroed on drop
    secret_key: SecretKey,
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
    let sig = arg_to_slice!(cx, 0);
    let bf = arg_to_slice!(cx, 1);

    let sig = handle_err!(BlindSignature::from_bytes(sig.as_slice()));
    let bf = handle_err!(SignatureBlinding::from_bytes(bf.as_slice()));

    let sig = sig.to_unblinded(&bf);

    let result = slice_to_js_array_buffer!(sig.to_bytes().as_slice(), cx);
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
///     "messages": [String, String]            // All messages that were signed in the order they correspond to the generators in the public key. They will be SHAKE-256 hashed
///     "revealed": [Number, Number]            // The zero based indices to the generators in the public key for the messages to be revealed. All other messages will be hidden from the verifier.
///     "nonce": String                         // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": String                           // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
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

    let pok = handle_err!(PoKOfSignature::init(&pcx.signature, &pk, &pcx.messages.as_slice(), None, &pcx.revealed.clone()));
    let mut challenge_bytes = pok.to_bytes();
    if let Some(b) = pcx.nonce {
        challenge_bytes.extend_from_slice(b.as_bytes());
    }

    let challenge_hash = SignatureMessage::from_msg_hash(&challenge_bytes);
    Ok(handle_err!(pok.gen_proof(&challenge_hash)))
}

fn extract_create_proof_context(cx: &mut FunctionContext) -> Result<CreateProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = handle_err!(Signature::from_bytes(&obj_field_to_slice!(cx, js_obj, "signature")));
    let public_key = DeterministicPublicKey::from_bytes(GenericArray::clone_from_slice(&obj_field_to_slice!(cx, js_obj, "publicKey")));
    let nonce = obj_field_to_opt_string!(cx, js_obj, "nonce");
    let t = obj_field_to_string!(cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));
    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.push(message);
    }

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = cast_to_number!(cx, revealed_indices[i]);
        if index < 0f64 || index as usize > messages.len() {
            panic!("Index is out of bounds. Must be between 0 and {}: {}", messages.len(), index);
        }
        revealed.insert(index as usize);
    }

    Ok(CreateProofContext {
        signature,
        public_key,
        messages,
        revealed,
        nonce,
        dst
    })
}

struct CreateProofContext {
    signature: Signature,
    public_key: DeterministicPublicKey,
    messages: Vec<SignatureMessage>,
    revealed: BTreeSet<usize>,
    nonce: Option<String>,
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
///     "messages": [String, String]            // The revealed messages as strings. They will be SHAKE-256 hashed.
///     "revealed": [Number, Number]            // The zero based indices to the generators in the public key for the messages to be revealed.
///     "nonce": String                         // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
///     "dst": String                           // The domain separation tag, e.g. "BBS-Sign-NewZealand2020
/// }
///
/// `return`: true if valid
fn bbs_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let vcx = extract_verify_proof_context(&mut cx)?;

    match verify_proof(vcx) {
        Ok(b) => match b {
            PoKOfSignatureProofStatus::Success => Ok(cx.boolean(true)),
            _ => Ok(cx.boolean(false))
        },
        Err(_) => Ok(cx.boolean(false)),
    }
}

fn verify_proof(vcx: VerifyProofContext) -> Result<PoKOfSignatureProofStatus,Throw> {
    let pk = vcx.public_key.to_public_key(vcx.message_count, vcx.dst.clone());
    let mut revealed_msgs = BTreeMap::new();
    for i in &vcx.revealed {
        revealed_msgs.insert(i.clone(), vcx.messages[*i].clone());
    }
    // The verifier generates the challenge on its own.
    let mut challenge_bytes = vcx.proof.get_bytes_for_challenge(vcx.revealed.clone(), &pk);

    if let Some(b) = vcx.nonce {
        challenge_bytes.extend_from_slice(b.as_bytes());
    }
    let challenge_verifier = SignatureMessage::from_msg_hash(&challenge_bytes);
    Ok(handle_err!(vcx.proof.verify(&pk, &revealed_msgs.clone(), &challenge_verifier)))
}

fn extract_verify_proof_context(cx: &mut FunctionContext) -> Result<VerifyProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = get_message_count!(cx, js_obj, "messageCount");
    let proof = handle_err!(PoKOfSignatureProof::from_bytes(&obj_field_to_slice!(cx, js_obj, "proof")));
    let public_key = DeterministicPublicKey::from_bytes(GenericArray::clone_from_slice(&obj_field_to_slice!(cx, js_obj, "publicKey")));
    let nonce = obj_field_to_opt_string!(cx, js_obj, "nonce");
    let t = obj_field_to_string!(cx, js_obj, "dst");
    let dst = handle_err!(DomainSeparationTag::new(t.as_bytes(), None, None, None));
    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.push(message);
    }

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = cast_to_number!(cx, revealed_indices[i]);
        if index < 0f64 || index > message_count {
            panic!("Index is out of bounds. Must be between 0 and {}: {}", message_count, index);
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
        nonce,
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
    nonce: Option<String>,
}

register_module!(mut m, {
    m.export_function("bls_generate_key", bls_generate_key)?;
    m.export_function("bbs_sign", bbs_sign)?;
    m.export_function("bbs_verify", bbs_verify)?;
    m.export_function("bbs_blind_signature_commitment", bbs_blind_signature_commitment)?;
    m.export_function("bbs_blind_sign", bbs_blind_sign)?;
    m.export_function("bbs_get_unblinded_signature", bbs_get_unblinded_signature)?;
    m.export_function("bbs_create_proof", bbs_create_proof)?;
    m.export_function("bbs_verify_proof", bbs_verify_proof)?;
    Ok(())
});
