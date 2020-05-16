/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate bbs;
#[macro_use]
mod macros;

use bbs::prelude::*;
use neon::prelude::*;
use neon::register_module;
use neon::result::Throw;
use std::collections::{BTreeMap, BTreeSet};

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

    let pk_array = slice_to_js_array_buffer!(&pk.to_bytes_compressed_form()[..], cx);
    let sk_array = slice_to_js_array_buffer!(&sk.to_bytes_compressed_form()[..], cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "publicKey", pk_array)?;
    result.set(&mut cx, "secretKey", sk_array)?;

    Ok(result)
}

/// Get the BBS public key associated with the private key
/// the context object model is as follows:
/// {
///     "secretKey": ArrayBuffer           // the private key of signer
///     "messageCount": Number,            // the number of messages that can be signed
/// }
/// `return`: `publickey` `arraybuffer`
fn bls_secret_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = get_message_count!(&mut cx, js_obj, "messageCount");
    let sk = SecretKey::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "secretKey",
        0,
        FR_COMPRESSED_SIZE
    ));

    let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));

    let pk = dpk.to_public_key(message_count as usize).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    Ok(slice_to_js_array_buffer!(
        &pk.to_bytes_compressed_form()[..],
        cx
    ))
}

/// Get the BBS public key associated with the public key
/// /// the context object model is as follows:
/// {
///     "publicKey": ArrayBuffer           // the public key of signer
///     "messageCount": Number,            // the number of messages that can be signed
/// }
/// `return`: `publicKey` `ArrayBuffer`
fn bls_public_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let message_count = get_message_count!(&mut cx, js_obj, "messageCount");
    let dpk = DeterministicPublicKey::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "publicKey",
        0,
        DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
    ));

    let pk = dpk.to_public_key(message_count as usize).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    Ok(slice_to_js_array_buffer!(
        &pk.to_bytes_compressed_form()[..],
        cx
    ))
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
///     "publicKey": ArrayBuffer           // The public key of signer
///     "messages": [String, String],      // The messages to be signed as strings. They will be hashed with SHAKE-256
/// }
///
/// `return`: `ArrayBuffer` the signature
fn bbs_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let sk = SecretKey::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "secretKey",
        0,
        FR_COMPRESSED_SIZE
    ));

    let pk_bytes = obj_field_to_slice!(&mut cx, js_obj, "publicKey");
    let pk = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(&mut cx, message_bytes[i]);
        messages.push(message);
    }

    let signature = handle_err!(Signature::new(messages.as_slice(), &sk, &pk));
    let result = slice_to_js_array_buffer!(&signature.to_bytes_compressed_form()[..], cx);
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
/// }
///
/// `return`: true if valid `signature` on `messages`
fn bbs_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = Signature::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "signature",
        0,
        SIGNATURE_COMPRESSED_SIZE
    ));

    let pk_bytes = obj_field_to_slice!(&mut cx, js_obj, "publicKey");
    let pk = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(&mut cx, message_bytes[i]);
        messages.push(message);
    }

    match signature.verify(messages.as_slice(), &pk) {
        Ok(b) => Ok(cx.boolean(b)),
        Err(_) => Ok(cx.boolean(false)),
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
///     "messages": [String, String],           // The messages that will be blinded as strings. They will be SHAKE-256 hashed
///     "blinded": [Number, Number],            // The zero based indices to the generators in the public key for the messages.
///     "nonce": String                         // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
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
    let (bcx, bf) =
        Prover::new_blind_signature_context(&bcx.public_key, &bcx.messages, &bcx.nonce).unwrap();
    get_blind_commitment(cx, bcx, bf)
}

fn get_blind_commitment(
    mut cx: FunctionContext,
    bcx: BlindSignatureContext,
    bf: SignatureBlinding,
) -> JsResult<JsObject> {
    let commitment = slice_to_js_array_buffer!(&bcx.commitment.to_bytes_compressed_form()[..], cx);
    let challenge_hash =
        slice_to_js_array_buffer!(&bcx.challenge_hash.to_bytes_compressed_form()[..], cx);
    let blinding_factor = slice_to_js_array_buffer!(&bf.to_bytes_compressed_form()[..], cx);
    let proof = slice_to_js_array_buffer!(
        bcx.proof_of_hidden_messages
            .to_bytes_compressed_form()
            .as_slice(),
        cx
    );

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "commitment", commitment)?;
    result.set(&mut cx, "challengeHash", challenge_hash)?;
    result.set(&mut cx, "blindingFactor", blinding_factor)?;
    result.set(&mut cx, "proofOfHiddenMessages", proof)?;
    Ok(result)
}

fn extract_blinding_context(cx: &mut FunctionContext) -> Result<BlindingContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let pk_bytes = obj_field_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();

    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let nonce_str = obj_field_to_opt_string!(cx, js_obj, "nonce");

    let hidden = obj_field_to_vec!(cx, js_obj, "blinded");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    if hidden.len() != message_bytes.len() {
        panic!(
            "hidden length is not the same as messages: {} != {}",
            hidden.len(),
            message_bytes.len()
        );
    }

    let mut messages = BTreeMap::new();
    let message_count = public_key.message_count() as f64;

    for i in 0..hidden.len() {
        let index = cast_to_number!(cx, hidden[i]);
        if index < 0f64 || index > message_count {
            panic!(
                "Index is out of bounds. Must be between {} and {}: found {}",
                0,
                public_key.message_count(),
                index
            );
        }
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.insert(index as usize, message);
    }
    let nonce = ProofNonce::hash(
        &(nonce_str.map_or_else(
            || "bbs+nodejswrapper".as_bytes().to_vec(),
            |m| m.as_bytes().to_vec(),
        )),
    );

    Ok(BlindingContext {
        public_key,
        messages,
        nonce,
    })
}

struct BlindingContext {
    public_key: PublicKey,
    messages: BTreeMap<usize, SignatureMessage>,
    nonce: ProofNonce,
}

/// Verify the proof of hidden messages and commitment send from calling
/// `bbs_blind_signature_commitment`. Signer should call this before creating a blind signature
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "commitment": ArrayBuffer,              // Commitment of hidden messages
///     "proofOfHiddenMessages": ArrayBuffer,   // Proof of commitment to hidden messages
///     "challengeHash": ArrayBuffer,           // Fiat-Shamir Challenge
///     "publicKey": ArrayBuffer                // The public key of signer
///     "blinded": [Number, Number],            // The zero based indices to the generators in the public key for the blinded messages.
///     "nonce": String                         // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
/// `return`: true if valid `signature` on `messages`
fn bbs_verify_blind_signature_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let js_obj = cx.argument::<JsObject>(0)?;
    let pk_bytes = obj_field_to_slice!(&mut cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let nonce_str = obj_field_to_opt_string!(&mut cx, js_obj, "nonce");
    let nonce = ProofNonce::hash(
        &(nonce_str.map_or_else(
            || "bbs+nodejswrapper".as_bytes().to_vec(),
            |m| m.as_bytes().to_vec(),
        )),
    );
    let commitment = Commitment::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "commitment",
        0,
        G1_COMPRESSED_SIZE
    ));
    let challenge_hash = ProofChallenge::from(obj_field_to_fixed_array!(
        &mut cx,
        js_obj,
        "commitment",
        0,
        FR_COMPRESSED_SIZE
    ));

    let proof_of_hidden_messages = handle_err!(ProofG1::from_bytes_compressed_form(
        &obj_field_to_slice!(&mut cx, js_obj, "proofOfHiddenMessages")
    ));

    let hidden = obj_field_to_vec!(&mut cx, js_obj, "blinded");
    let mut messages = BTreeMap::new();
    let message_count = public_key.message_count() as f64;

    for i in 0..hidden.len() {
        let index = cast_to_number!(cx, hidden[i]);
        if index < 0f64 || index > message_count {
            panic!(
                "Index is out of bounds. Must be between {} and {}: found {}",
                0,
                public_key.message_count(),
                index
            );
        }
        messages.insert(index as usize, SignatureMessage::from([0u8; FR_COMPRESSED_SIZE]));
    }

    let ctx = BlindSignatureContext {
        commitment,
        challenge_hash,
        proof_of_hidden_messages,
    };

    match ctx.verify(&messages, &public_key, &nonce) {
        Ok(b) => Ok(cx.boolean(b)),
        Err(_) => Ok(cx.boolean(false)),
    }
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
///     "publicKey": ArrayBuffer                 // The public key of signer
///     "secretKey": ArrayBuffer                 // The secret key used for generating the signature
///     "messages": [String, String]             // The messages that will be signed as strings. They will be hashed with SHAKE-256
///     "known": [Number, Number],              // The zero based indices to the generators in the public key for the known messages.
/// }
///
/// `return`: `ArrayBuffer` the blinded signature. Recipient must unblind before it is valid
fn bbs_blind_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let bcx = extract_blind_signature_context(&mut cx)?;
    let signature = handle_err!(BlindSignature::new(
        &bcx.commitment,
        &bcx.messages,
        &bcx.secret_key,
        &bcx.public_key
    ));
    let result = slice_to_js_array_buffer!(&signature.to_bytes_compressed_form()[..], cx);
    Ok(result)
}

fn extract_blind_signature_context(cx: &mut FunctionContext) -> Result<BlindSignContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let secret_key = SecretKey::from(obj_field_to_fixed_array!(
        cx,
        js_obj,
        "secretKey",
        0,
        FR_COMPRESSED_SIZE
    ));

    let pk_bytes = obj_field_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let known = obj_field_to_vec!(cx, js_obj, "known");
    if known.len() != message_bytes.len() {
        panic!(
            "known length != messages: {} != {}",
            known.len(),
            message_bytes.len()
        );
    }

    let message_count = public_key.message_count() as f64;
    let mut messages = BTreeMap::new();

    for i in 0..known.len() {
        let index = cast_to_number!(cx, known[i]);
        if index < 0f64 || index > message_count {
            panic!(
                "Index is out of bounds. Must be between {} and {}: found {}",
                0,
                public_key.message_count(),
                index
            );
        }
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.insert(index as usize, message);
    }

    let commitment = Commitment::from(obj_field_to_fixed_array!(
        cx,
        js_obj,
        "commitment",
        0,
        G1_COMPRESSED_SIZE
    ));

    Ok(BlindSignContext {
        commitment,
        messages,
        public_key,
        secret_key,
    })
}

struct BlindSignContext {
    commitment: Commitment,
    public_key: PublicKey,
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
    let sig = BlindSignature::from(arg_to_fixed_array!(cx, 0, 0, SIGNATURE_COMPRESSED_SIZE));
    let bf = SignatureBlinding::from(arg_to_fixed_array!(
        cx,
        1,
        0,
        FR_COMPRESSED_SIZE
    ));

    let sig = sig.to_unblinded(&bf);

    let result = slice_to_js_array_buffer!(&sig.to_bytes_compressed_form()[..], cx);
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
/// }
///
/// `return`: `ArrayBuffer` the proof to send to the verifier
fn bbs_create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let (mut bitvector, pcx) = extract_create_proof_context(&mut cx)?;
    let proof = generate_proof(pcx)?;
    bitvector.extend_from_slice(proof.to_bytes_compressed_form().as_slice());
    Ok(slice_to_js_array_buffer!(
        bitvector.as_slice(),
        cx
    ))
}

fn generate_proof(pcx: CreateProofContext) -> Result<PoKOfSignatureProof, Throw> {
    let pok = handle_err!(PoKOfSignature::init(
        &pcx.signature,
        &pcx.public_key,
        &pcx.messages.as_slice()
    ));
    let mut challenge_bytes = pok.to_bytes();
    if let Some(b) = pcx.nonce {
        challenge_bytes.extend_from_slice(&ProofNonce::hash(b.as_bytes()).to_bytes_compressed_form());
    } else {
        challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
    }

    let challenge_hash = ProofChallenge::hash(&challenge_bytes);
    Ok(handle_err!(pok.gen_proof(&challenge_hash)))
}

fn extract_create_proof_context(cx: &mut FunctionContext) -> Result<(Vec<u8>, CreateProofContext), Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = Signature::from(obj_field_to_fixed_array!(
        cx,
        js_obj,
        "signature",
        0,
        SIGNATURE_COMPRESSED_SIZE
    ));
    let pk_bytes = obj_field_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

    let nonce = obj_field_to_opt_string!(cx, js_obj, "nonce");

    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = cast_to_number!(cx, revealed_indices[i]);
        if index < 0f64 || index as usize > message_bytes.len() {
            panic!(
                "Index is out of bounds. Must be between 0 and {}: {}",
                message_bytes.len(),
                index
            );
        }
        revealed.insert(index as usize);
    }

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        if revealed.contains(&i) {
            messages.push(pm_revealed_raw!(message));
        } else {
            messages.push(pm_hidden_raw!(message));
        }
    }

    let mut bitvector = (messages.len() as u16).to_be_bytes().to_vec();
    bitvector.append(&mut revealed_to_bitvector(messages.len(), &revealed));

    Ok((bitvector, CreateProofContext {
        signature,
        public_key,
        messages,
        nonce,
    }))
}

struct CreateProofContext {
    signature: Signature,
    public_key: PublicKey,
    messages: Vec<ProofMessage>,
    nonce: Option<String>,
}

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer in BLS form
///     "messages": [String, String]            // The revealed messages as strings. They will be Blake2b hashed.
///     "nonce": String                         // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: true if valid
fn bls_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let vcx = extract_verify_proof_context(&mut cx, true)?;

    match verify_proof(vcx) {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false)),
    }
}

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer
///     "messages": [String, String]            // The revealed messages as strings. They will be Blake2b hashed.
///     "nonce": String                         // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: true if valid
fn bbs_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let vcx = extract_verify_proof_context(&mut cx, false)?;

    match verify_proof(vcx) {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false)),
    }
}

fn verify_proof(vcx: VerifyProofContext) -> Result<Vec<SignatureMessage>, Throw> {
    let nonce = match vcx.nonce {
        Some(ref s) => ProofNonce::hash(s.as_bytes()),
        None => ProofNonce::from([0u8; FR_COMPRESSED_SIZE]),
    };
    let proof_request = ProofRequest {
        revealed_messages: vcx.revealed.clone(),
        verification_key: vcx.public_key.clone(),
    };

    let revealed = vcx.revealed.iter().collect::<Vec<&usize>>();
    let mut revealed_messages = BTreeMap::new();
    for i in 0..vcx.revealed.len() {
        revealed_messages.insert(*revealed[i], vcx.messages[i].clone());
    }

    let signature_proof = SignatureProof {
        revealed_messages,
        proof: vcx.proof.clone(),
    };

    Ok(handle_err!(Verifier::verify_signature_pok(
        &proof_request,
        &signature_proof,
        &nonce,
    )))
}

fn extract_verify_proof_context(cx: &mut FunctionContext, is_bls: bool) -> Result<VerifyProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let proof = obj_field_to_slice!(cx, js_obj, "proof");
    let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;
    let bitvector_length = (message_count / 8) + 1;
    let offset = 2 + bitvector_length;
    let revealed = bitvector_to_revealed(&proof[2..offset]);

    let proof = handle_err!(PoKOfSignatureProof::from_bytes_compressed_form(&proof[offset..]));

    let nonce = obj_field_to_opt_string!(cx, js_obj, "nonce");
    // let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = obj_field_to_field_elem!(cx, message_bytes[i]);
        messages.push(message);
    }

    let public_key = if is_bls {
        let dpk = DeterministicPublicKey::from(obj_field_to_fixed_array!(
            cx,
            js_obj,
            "publicKey",
            0,
            DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
        ));
        dpk.to_public_key(message_count).unwrap()
    } else {
        let pk_bytes = obj_field_to_slice!(cx, js_obj, "publicKey");
        PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap()
    };
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

    // let message_count = public_key.message_count() as f64;
    // let mut revealed = BTreeSet::new();
    // for i in 0..revealed_indices.len() {
    //     let index = cast_to_number!(cx, revealed_indices[i]);
    //     if index < 0f64 || index > message_count {
    //         panic!(
    //             "Index is out of bounds. Must be between 0 and {}: {}",
    //             message_count, index
    //         );
    //     }
    //     revealed.insert(index as usize);
    // }

    Ok(VerifyProofContext {
        proof,
        public_key,
        messages,
        revealed,
        nonce,
    })
}

struct VerifyProofContext {
    messages: Vec<SignatureMessage>,
    proof: PoKOfSignatureProof,
    public_key: PublicKey,
    revealed: BTreeSet<usize>,
    nonce: Option<String>,
}

/// Expects `revealed` to be sorted
fn revealed_to_bitvector(total: usize, revealed: &BTreeSet<usize>) -> Vec<u8> {
    let mut bytes = vec![0u8; (total / 8) + 1];

    for r in revealed {
        let idx = *r / 8;
        let bit = (*r % 8) as u8;
        bytes[idx] |= 1u8 << bit;
    }

    // Convert to big endian
    bytes.reverse();
    bytes
}

/// Convert big-endian vector to u32
fn bitvector_to_revealed(data: &[u8]) -> BTreeSet<usize> {
    let mut revealed_messages = BTreeSet::new();
    let mut scalar = 0;

    for b in data.iter().rev() {
        let mut v = *b;
        let mut remaining = 8;
        while v > 0 {
            let revealed = v & 1u8;
            if revealed == 1 {
                revealed_messages.insert(scalar);
            }
            v >>= 1;
            scalar += 1;
            remaining -= 1;
        }
        scalar += remaining;
    }
    revealed_messages
}

register_module!(mut m, {
    m.export_function("bls_generate_key", bls_generate_key)?;
    m.export_function("bls_secret_key_to_bbs_key", bls_secret_key_to_bbs_key)?;
    m.export_function("bls_public_key_to_bbs_key", bls_public_key_to_bbs_key)?;
    m.export_function("bbs_sign", bbs_sign)?;
    m.export_function("bbs_verify", bbs_verify)?;
    m.export_function(
        "bbs_blind_signature_commitment",
        bbs_blind_signature_commitment,
    )?;
    m.export_function(
        "bbs_verify_blind_signature_proof",
        bbs_verify_blind_signature_proof,
    )?;
    m.export_function("bbs_blind_sign", bbs_blind_sign)?;
    m.export_function("bbs_get_unblinded_signature", bbs_get_unblinded_signature)?;
    m.export_function("bbs_create_proof", bbs_create_proof)?;
    m.export_function("bbs_verify_proof", bbs_verify_proof)?;
    m.export_function("bls_verify_proof", bls_verify_proof)?;
    Ok(())
});
