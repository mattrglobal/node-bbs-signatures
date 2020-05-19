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

use bbs::prelude::*;
use std::collections::BTreeSet;

/// Computed by calling
///
/// SecretKey::hash(b"aaaaaaaa");
const SECRET_KEY: &str = "csxPwY1AGplWf2efwLRRosnGmzcufHUSHr+bdz3xKQI=";

/// Computed by calling
///
/// let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
///
/// where `sk` = base64::decode(SECRET_KEY);
const PUBLIC_KEY: &str = "q4OA1O/iLQyZkwil2XatmWC1nWVSml3rd9UKV8zfy0hKOuzxpq0dJZhbRCp3tvCIGOkpRfSXKbUU9ns93QUas8n16nv6voGvffPNezqhnYknkzlnp2CwXgsEuVMp01l5";

#[test]
fn verify_single_message() {
    const SIGNATURE: &str = "rRcuRnYdwerxuywxOKmRmpmKTVM8SlG8deJNK0lfzs3+hneLwGicrkjc3w4bZnc6SvGwdMH7xZawlMQVtMUEZW+4R7lU7L6vyYGAEHb2jyA+5PihP618CMbPgq2SkIPkDOU2WknrpdZpFbqzfe2erQ==";
    let messages = vec![SignatureMessage::hash(b"ExampleMessage")];

    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);

    assert!(sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn no_verify_valid_signature_with_wrong_single_message() {
    const SIGNATURE: &str = "rRcuRnYdwerxuywxOKmRmpmKTVM8SlG8deJNK0lfzs3+hneLwGicrkjc3w4bZnc6SvGwdMH7xZawlMQVtMUEZW+4R7lU7L6vyYGAEHb2jyA+5PihP618CMbPgq2SkIPkDOU2WknrpdZpFbqzfe2erQ==";
    let messages = vec![SignatureMessage::hash(b"BadMessage")];

    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);
    assert!(!sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn verify_valid_signature_with_multiple_messages() {
    const SIGNATURE: &str  = "r/h/EGXheiRm0Ku78HyYd6cHRUPdJoZcbqbNdcrHd+vfUgcHZ7DYxz/BPJvUey9IRpUj/0aDBk1Wu8GigfqTVcqnVZhtyjCwIKklMl47pCBSyV4qvnBKEWV/rWFcbuJxyiwGSyrMNj6ik2Kh7QKoIQ==";

    let messages = vec![
        SignatureMessage::hash(b"ExampleMessage"),
        SignatureMessage::hash(b"ExampleMessage2"),
        SignatureMessage::hash(b"ExampleMessage3"),
    ];

    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);

    assert!(sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn no_verify_valid_signature_with_wrong_messages() {
    const SIGNATURE: &str  = "r/h/EGXheiRm0Ku78HyYd6cHRUPdJoZcbqbNdcrHd+vfUgcHZ7DYxz/BPJvUey9IRpUj/0aDBk1Wu8GigfqTVcqnVZhtyjCwIKklMl47pCBSyV4qvnBKEWV/rWFcbuJxyiwGSyrMNj6ik2Kh7QKoIQ==";

    let messages = vec![
        SignatureMessage::hash(b"BadMessage"),
        SignatureMessage::hash(b"BadMessage"),
        SignatureMessage::hash(b"BadMessage"),
    ];

    let dpk = get_public_key(PUBLIC_KEY);
    let sig = get_signature(SIGNATURE);

    let pk = dpk.to_public_key(messages.len()).unwrap();
    assert!(!sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn proof_revealing_single_message_from_single_message_signature() {
    const SIGNATURE: &str = "rRcuRnYdwerxuywxOKmRmpmKTVM8SlG8deJNK0lfzs3+hneLwGicrkjc3w4bZnc6SvGwdMH7xZawlMQVtMUEZW+4R7lU7L6vyYGAEHb2jyA+5PihP618CMbPgq2SkIPkDOU2WknrpdZpFbqzfe2erQ==";

    let messages = vec![pm_revealed!(b"ExampleMessage")];
    let nonce = ProofNonce::hash(b"0123456789");

    let dpk = get_public_key(PUBLIC_KEY);
    let sig = get_signature(SIGNATURE);

    let pk = dpk.to_public_key(messages.len()).unwrap();
    let pr = Verifier::new_proof_request(&[0], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

    let challenge = ProofChallenge::hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes_compressed_form();

    assert_eq!(proof_bytes.len(), 380);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(
        proved_messages,
        vec![SignatureMessage::hash(b"ExampleMessage")]
    )
}

#[test]
fn proof_revealing_single_message_from_multiple_message_signature() {
    const SIGNATURE: &str  = "r/h/EGXheiRm0Ku78HyYd6cHRUPdJoZcbqbNdcrHd+vfUgcHZ7DYxz/BPJvUey9IRpUj/0aDBk1Wu8GigfqTVcqnVZhtyjCwIKklMl47pCBSyV4qvnBKEWV/rWFcbuJxyiwGSyrMNj6ik2Kh7QKoIQ==";

    let messages = vec![
        pm_revealed!(b"ExampleMessage"),
        pm_hidden!(b"ExampleMessage2"),
        pm_hidden!(b"ExampleMessage3"),
    ];
    let nonce = ProofNonce::hash(b"0123456789");

    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);

    let pr = Verifier::new_proof_request(&[0], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

    let challenge = ProofChallenge::hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes_compressed_form();

    assert_eq!(proof_bytes.len(), 444);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(
        proved_messages,
        vec![SignatureMessage::hash(b"ExampleMessage")]
    )
}

#[test]
fn proof_with_10_messages() {
    const SIGNATURE: &str = "l26W5/CWylRvLz+3UaRvr5VyUXMzFl84Nl19DfhfzTnAYtUGh8nX3k708CrLt8EEAIoCkUTk4pCGKEqUeCdhdv3v6udRscMgSdkZ/JWhXs4Dc2CLXy4XCRNDTcvuqmTbi2hEuVQgGrb1snItjVMUhw==";
    let messages = vec![
        pm_hidden!(b"Message0"),
        pm_hidden!(b"Message1"),
        pm_hidden!(b"Message2"),
        pm_hidden!(b"Message3"),
        pm_hidden!(b"Message4"),
        pm_hidden!(b"Message5"),
        pm_hidden!(b"Message6"),
        pm_hidden!(b"Message8"),
        pm_hidden!(b"Message8"),
        pm_revealed!(b"Message9"),
    ];

    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);

    let nonce = ProofNonce::hash(b"0123456789");
    let pr = Verifier::new_proof_request(&[9], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

    let challenge = ProofChallenge::hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes_compressed_form();

    assert_eq!(proof_bytes.len(), 668);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(
        proved_messages,
        vec![SignatureMessage::hash(b"Message9")]
    )
}

#[test]
fn proof_with_8_messages() {
    const SIGNATURE: &str = "kQv6mualVu5VPRfyRPToLcgcdGW4iMuUhXXs7W+O0V4hMmo0yBPiBNLStfFyZQZpbgbICxAMYnbowlF4EKdI8zne2NIcyBAQ/47OI8Y1JhlQL4GRLvR+4725M4V2Pi0T7GCNr9nnxKg8vrAG1x+UXQ==";

    let messages = vec![
        pm_revealed!(b"Message0"),
        pm_revealed!(b"Message1"),
        pm_revealed!(b"Message2"),
        pm_hidden!(b"Message3"),
        pm_revealed!(b"Message4"),
        pm_hidden!(b"Message5"),
        pm_revealed!(b"Message6"),
        pm_hidden!(b"Message7"),
    ];
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = get_signature(SIGNATURE);

    let nonce = ProofNonce::hash(b"0123456789");
    let pr = Verifier::new_proof_request(&[0, 1, 2, 4, 6], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

    let challenge = ProofChallenge::hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes_compressed_form();

    assert_eq!(proof_bytes.len(), 476);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    // let proved_messages = res.unwrap();
    // assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"Message9")])
}

#[test]
fn print() {
    let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::UseSeed(base64::decode("H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=").unwrap())));
    println!("sk  = {}", base64::encode(sk.to_bytes_compressed_form().as_ref()));
    println!("dpk = {}", base64::encode(dpk.to_bytes_compressed_form().as_ref()));
    let messages: Vec<SignatureMessage> = ["KNK0ITRAF+NrGg=="].iter().map(|m| SignatureMessage::hash(m.as_bytes())).collect();
    let pk = dpk.to_public_key(messages.len()).unwrap();
    let sig = Signature::new(messages.as_slice(), &sk, &pk).unwrap();
    println!("pk  = {}", base64::encode(pk.to_bytes_compressed_form()));
    println!("sig = {}", base64::encode(sig.to_bytes_compressed_form().as_ref()));
    let nonce = ProofNonce::hash(b"v3bb/Mz+JajUdiM2URfZYcPuqxw=");
    let proof_request = Verifier::new_proof_request(&[0], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        pm_revealed_raw!(messages[0]),
        // pm_revealed_raw!(messages[1]),
        // pm_revealed_raw!(messages[2]),
    //     pm_hidden!(b"Message4"),
    ];

    let pok =
        Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &sig).unwrap();

    // complete other zkps as desired and compute `challenge_hash`
    // add bytes from other proofs

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

    let challenge = ProofChallenge::hash(&challenge_bytes);

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();
    let mut prefix = (messages.len() as u16).to_be_bytes().to_vec();
    prefix.append(&mut revealed_to_bitvector(messages.len(), &proof_request.revealed_messages));
    prefix.extend_from_slice(proof.proof.to_bytes_compressed_form().as_ref());
    println!(
        "proof = {}",
        base64::encode(&prefix)
    );

    let res = Verifier::verify_signature_pok(&proof_request, &proof, &nonce);

    assert!(res.is_ok());
    // let proved_messages = res.unwrap();

    // proof_request.revealed_messages = BTreeSet::new();
    // proof_request.revealed_messages.insert(1);
    // proof.revealed_messages = vec![SignatureMessage::from_msg_hash(b"Message2")];
}

fn get_public_key(key: &str) -> DeterministicPublicKey {
    let dpk_bytes = base64::decode(key).unwrap();
    DeterministicPublicKey::from(*array_ref![
        dpk_bytes,
        0,
        DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
    ])
}

fn get_secret_key(key: &str) -> SecretKey {
    let sk_bytes = base64::decode(key).unwrap();
    SecretKey::from(array_ref![sk_bytes, 0, FR_COMPRESSED_SIZE])
}

fn get_signature(sig: &str) -> Signature {
    let sig_bytes = base64::decode(sig).unwrap();
    Signature::from(*array_ref![sig_bytes, 0, SIGNATURE_COMPRESSED_SIZE])
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