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
use neon::result::Throw;
use neon::types::buffer::TypedArray;
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::{thread_rng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

// This shows how the generators are created with nothing up my sleeve values
// const PREHASH: &'static [u8] = b"To be, or not to be- that is the question:
// Whether 'tis nobler in the mind to suffer
// The slings and arrows of outrageous fortune
// Or to take arms against a sea of troubles,
// And by opposing end them. To die- to sleep-
// No more; and by a sleep to say we end
// The heartache, and the thousand natural shocks
// That flesh is heir to. 'Tis a consummation
// Devoutly to be wish'd. To die- to sleep.
// To sleep- perchance to dream: ay, there's the rub!
// For in that sleep of death what dreams may come
// When we have shuffled off this mortal coil,
// Must give us pause. There's the respect
// That makes calamity of so long life.
// For who would bear the whips and scorns of time,
// Th' oppressor's wrong, the proud man's contumely,
// The pangs of despis'd love, the law's delay,
// The insolence of office, and the spurns
// That patient merit of th' unworthy takes,
// When he himself might his quietus make
// With a bare bodkin? Who would these fardels bear,
// To grunt and sweat under a weary life,
// But that the dread of something after death-
// The undiscover'd country, from whose bourn
// No traveller returns- puzzles the will,
// And makes us rather bear those ills we have
// Than fly to others that we know not of?
// Thus conscience does make cowards of us all,
// And thus the native hue of resolution
// Is sicklied o'er with the pale cast of thought,
// And enterprises of great pith and moment
// With this regard their currents turn awry
// And lose the name of action.- Soft you now!
// The fair Ophelia!- Nymph, in thy orisons
// Be all my sins rememb'red.";
// const DST_G1: &'static [u8] = b"BLS12381G1_XMD:BLAKE2B_SSWU_RO_BLS_SIGNATURES:1_0_0";
// const DST_G2: &'static [u8] = b"BLS12381G2_XMD:BLAKE2B_SSWU_RO_BLS_SIGNATURES:1_0_0";
//
// fn main() {
//     let g1 = <G1 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(PREHASH, DST_G1);
//     let g2 = <G2 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(PREHASH, DST_G2);
//
//     let mut g1_bytes = Vec::new();
//     let mut g2_bytes = Vec::new();
//
//     g1.serialize(&mut g1_bytes, true).unwrap();
//     g2.serialize(&mut g2_bytes, true).unwrap();
//
//     println!("g1 = {}", hex::encode(g1_bytes.as_slice()));
//     println!("g2 = {}", hex::encode(g2_bytes.as_slice()));
// }
// g1 = b9c9058e8a44b87014f98be4e1818db718f8b2d5101fc89e6983625f321f14b84d7cf6e155004987a215ee426df173c9
// g2 = a963de2adfb1163cf4bed24d708ce47432742d2080b2573ebe2e19a8698f60c541cec000fcb19783e9be73341356df5f1191cddec7c476d7742bcc421afc5d505e63373c627ea01fda04f0e40159d25bdd12f45a010d8580a78f6a7d262272f3

const BLINDING_G1: &[u8] = &[
    185, 201, 5, 142, 138, 68, 184, 112, 20, 249, 139, 228, 225, 129, 141, 183, 24, 248, 178, 213,
    16, 31, 200, 158, 105, 131, 98, 95, 50, 31, 20, 184, 77, 124, 246, 225, 85, 0, 73, 135, 162,
    21, 238, 66, 109, 241, 115, 201,
];
const BLINDING_G2: &[u8] = &[
    169, 99, 222, 42, 223, 177, 22, 60, 244, 190, 210, 77, 112, 140, 228, 116, 50, 116, 45, 32,
    128, 178, 87, 62, 190, 46, 25, 168, 105, 143, 96, 197, 65, 206, 192, 0, 252, 177, 151, 131,
    233, 190, 115, 52, 19, 86, 223, 95, 17, 145, 205, 222, 199, 196, 118, 215, 116, 43, 204, 66,
    26, 252, 93, 80, 94, 99, 55, 60, 98, 126, 160, 31, 218, 4, 240, 228, 1, 89, 210, 91, 221, 18,
    244, 90, 1, 13, 133, 128, 167, 143, 106, 125, 38, 34, 114, 243,
];

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g2` ^ `x` * `blinding_g2` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g2_key(cx: FunctionContext) -> JsResult<JsObject> {
    bls_generate_keypair::<G2>(cx, Some(BLINDING_G2))
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g1` ^ `x` * `blinding_g1` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g1_key(cx: FunctionContext) -> JsResult<JsObject> {
    bls_generate_keypair::<G1>(cx, Some(BLINDING_G1))
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g2_key(cx: FunctionContext) -> JsResult<JsObject> {
    bls_generate_keypair::<G2>(cx, None)
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g1` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g1_key(cx: FunctionContext) -> JsResult<JsObject> {
    bls_generate_keypair::<G1>(cx, None)
}

fn bls_generate_keypair<'a, G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    mut cx: FunctionContext<'a>,
    blinded: Option<&[u8]>,
) -> JsResult<'a, JsObject> {
    let mut passed_seed = false;
    let seed = match cx.argument_opt(0) {
        Some(arg) => {
            let arg: Handle<JsArrayBuffer> = arg.downcast_or_throw(&mut cx)?;
            let seed_data = arg.as_slice(&cx);
            passed_seed = true;
            seed_data.to_vec()
        }
        None => {
            let mut rng = thread_rng();
            let mut seed_data = vec![0u8, 32];
            rng.fill_bytes(seed_data.as_mut_slice());
            seed_data
        }
    };

    let sk = gen_sk(seed.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let r = match blinded {
        Some(g) => {
            let mut data = g.to_vec();
            let mut gg = g;
            if passed_seed {
                data.extend_from_slice(seed.as_slice());
            } else {
                let mut rng = thread_rng();
                let mut blinding_factor = vec![0u8, 32];
                rng.fill_bytes(blinding_factor.as_mut_slice());
                data.extend_from_slice(blinding_factor.as_slice());
            }
            let mut blinding_g = G::deserialize(&mut gg, true).unwrap();
            let r = gen_sk(data.as_slice());
            blinding_g.mul_assign(r);
            pk.add_assign(&blinding_g);
            Some(r)
        }
        None => None,
    };

    let mut sk_bytes = Vec::new();
    let mut pk_bytes = Vec::new();
    sk.serialize(&mut sk_bytes, true).unwrap();
    pk.serialize(&mut pk_bytes, true).unwrap();
    let pk_array = slice_to_js_array_buffer!(&pk_bytes[..], cx);
    let sk_array = slice_to_js_array_buffer!(&sk_bytes[..], cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "publicKey", pk_array)?;
    result.set(&mut cx, "secretKey", sk_array)?;
    if let Some(rr) = r {
        let mut r_bytes = Vec::new();
        rr.serialize(&mut r_bytes, true).unwrap();
        let r_array = slice_to_js_array_buffer!(&r_bytes[..], cx);
        result.set(&mut cx, "blindingFactor", r_array)?;
    }

    Ok(result)
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
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
///     "secretKey": ArrayBuffer                // The private key of signer
///     "publicKey": ArrayBuffer                // The public key of signer
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages to be signed as strings. They will be hashed with Blake2b
///     "secretKey": ArrayBuffer                // The private key of signer
///     "publicKey": ArrayBuffer                // The public key of signer
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages to be signed as ArrayBuffers. They will be hashed with Blake2b
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
    let pk = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for message_byte in message_bytes {
        let message = obj_field_to_field_elem!(&mut cx, message_byte);
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
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that were signed as strings. They will be Blake2b hashed
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that were signed as ArrayBuffers. They will be Blake2b hashed
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
    let pk = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();

    if pk.validate().is_err() {
        panic!("Invalid key");
    }

    let message_bytes = obj_field_to_vec!(&mut cx, js_obj, "messages");

    let mut messages = Vec::new();
    for message_byte in message_bytes {
        let message = obj_field_to_field_elem!(&mut cx, message_byte);
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
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that will be blinded as strings. They will be Blake2b hashed
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that will be blinded as ArrayBuffers. They will be Blake2b hashed
///     "blinded": [Number, Number],            // The zero based indices to the generators in the public key for the messages.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
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
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();

    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let nonce = obj_field_to_opt_slice!(cx, js_obj, "nonce");

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
    let nonce = ProofNonce::hash(nonce.map_or_else(|| b"bbs+nodejswrapper".to_vec(), |m| m));

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
///     "nonce": ArrayBuffer                    // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
/// `return`: true if valid `signature` on `messages`
fn bbs_verify_blind_signature_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let js_obj = cx.argument::<JsObject>(0)?;
    let pk_bytes = obj_field_to_slice!(&mut cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let nonce_str = obj_field_to_opt_slice!(&mut cx, js_obj, "nonce");
    let nonce = ProofNonce::hash(nonce_str.map_or_else(|| b"bbs+nodejswrapper".to_vec(), |m| m));
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
    let mut messages: BTreeSet<usize> = (0..public_key.message_count()).collect();
    let message_count = public_key.message_count() as f64;

    for hidden_value in hidden {
        let index = cast_to_number!(&mut cx, hidden_value);
        if index < 0f64 || index > message_count {
            panic!(
                "Index is out of bounds. Must be between {} and {}: found {}",
                0,
                public_key.message_count(),
                index
            );
        }
        messages.remove(&(index as usize));
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
///     "commitment": ArrayBuffer               // The commitment received from the intended recipient
///     "publicKey": ArrayBuffer                // The public key of signer
///     "secretKey": ArrayBuffer                // The secret key used for generating the signature
///     "messages": [ArrayBuffer, ArrayBuffer]  // The messages that will be signed as strings. They will be hashed with Blake2b
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
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();
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
    let bf = SignatureBlinding::from(arg_to_fixed_array!(cx, 1, 0, FR_COMPRESSED_SIZE));

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
///     "messages": [ArrayBuffer, ArrayBuffer]  // All messages that were signed in the order they correspond to the generators in the public key. They will be Blake2b hashed
///     "revealed": [Number, Number]            // The zero based indices to the generators in the public key for the messages to be revealed. All other messages will be hidden from the verifier.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: `ArrayBuffer` the proof to send to the verifier
fn bbs_create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let (mut bitvector, pcx) = extract_create_proof_context(&mut cx)?;
    let proof = generate_proof(pcx)?;
    bitvector.extend_from_slice(proof.to_bytes_compressed_form().as_slice());
    Ok(slice_to_js_array_buffer!(bitvector.as_slice(), cx))
}

fn generate_proof(pcx: CreateProofContext) -> Result<PoKOfSignatureProof, Throw> {
    let pok = handle_err!(PoKOfSignature::init(
        &pcx.signature,
        &pcx.public_key,
        pcx.messages.as_slice()
    ));
    let mut challenge_bytes = pok.to_bytes();
    if let Some(b) = pcx.nonce {
        challenge_bytes
            .extend_from_slice(&ProofNonce::hash(b.as_slice()).to_bytes_compressed_form());
    } else {
        challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
    }

    let challenge_hash = ProofChallenge::hash(&challenge_bytes);
    Ok(handle_err!(pok.gen_proof(&challenge_hash)))
}

fn extract_create_proof_context(
    cx: &mut FunctionContext,
) -> Result<(Vec<u8>, CreateProofContext), Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = Signature::from(obj_field_to_fixed_array!(
        cx,
        js_obj,
        "signature",
        0,
        SIGNATURE_COMPRESSED_SIZE
    ));
    let pk_bytes = obj_field_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

    let nonce = obj_field_to_opt_slice!(cx, js_obj, "nonce");

    let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    let mut revealed = BTreeSet::new();
    for revealed_indice in revealed_indices {
        let index = cast_to_number!(cx, revealed_indice);
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
    for (i, message_byte) in message_bytes.iter().enumerate() {
        let message = obj_field_to_field_elem!(cx, *message_byte);
        if revealed.contains(&i) {
            messages.push(pm_revealed_raw!(message));
        } else {
            messages.push(pm_hidden_raw!(message));
        }
    }

    let mut bitvector = (messages.len() as u16).to_be_bytes().to_vec();
    bitvector.append(&mut revealed_to_bitvector(messages.len(), &revealed));

    Ok((
        bitvector,
        CreateProofContext {
            signature,
            public_key,
            messages,
            nonce,
        },
    ))
}

struct CreateProofContext {
    signature: Signature,
    public_key: PublicKey,
    messages: Vec<ProofMessage>,
    nonce: Option<Vec<u8>>,
}

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer in BLS form
///     "messages": [ArrayBuffer, ArrayBuffer]  // The revealed messages as ArrayBuffers. They will be Blake2b hashed.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
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
///     "messages": [ArrayBuffer, ArrayBuffer]  // The revealed messages as ArrayBuffers. They will be Blake2b hashed.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
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
        Some(ref s) => ProofNonce::hash(s.as_slice()),
        None => ProofNonce::from([0u8; FR_COMPRESSED_SIZE]),
    };
    let proof_request = ProofRequest {
        revealed_messages: vcx.revealed.clone(),
        verification_key: vcx.public_key.clone(),
    };

    let revealed = vcx.revealed.iter().collect::<Vec<&usize>>();
    let mut revealed_messages = BTreeMap::new();
    for (i, revealed_index) in revealed
        .iter()
        .copied()
        .enumerate()
        .take(vcx.revealed.len())
    {
        revealed_messages.insert(*revealed_index, vcx.messages[i]);
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

fn extract_verify_proof_context(
    cx: &mut FunctionContext,
    is_bls: bool,
) -> Result<VerifyProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let proof = obj_field_to_slice!(cx, js_obj, "proof");
    let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;
    let bitvector_length = (message_count / 8) + 1;
    let offset = 2 + bitvector_length;
    let revealed = bitvector_to_revealed(&proof[2..offset]);

    let proof = handle_err!(PoKOfSignatureProof::from_bytes_compressed_form(
        &proof[offset..]
    ));

    let nonce = obj_field_to_opt_slice!(cx, js_obj, "nonce");
    // let revealed_indices = obj_field_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_field_to_vec!(cx, js_obj, "messages");

    if message_bytes.len() != revealed.len() {
        panic!("Given messages count ({}) is different from revealed messages count ({}) for this proof",
            message_bytes.len(), revealed.len());
    }

    let mut messages = Vec::new();
    for message_byte in message_bytes {
        let message = obj_field_to_field_elem!(cx, message_byte);
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
        PublicKey::from_bytes_compressed_form(pk_bytes).unwrap()
    };
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

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
    nonce: Option<Vec<u8>>,
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

#[neon::main]
fn main(mut m: ModuleContext) -> NeonResult<()> {
    m.export_function("bls_generate_blinded_g2_key", bls_generate_blinded_g2_key)?;
    m.export_function("bls_generate_blinded_g1_key", bls_generate_blinded_g1_key)?;
    m.export_function("bls_generate_g2_key", bls_generate_g2_key)?;
    m.export_function("bls_generate_g1_key", bls_generate_g1_key)?;
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
}
