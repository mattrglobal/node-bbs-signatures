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

const DOMAIN_SEPARATION_TAG: &str = "BBSSignature2020";
/// Computed by calling
///
/// SecretKey::from_msg_hash(b"aaaaaaaa");
const SECRET_KEY: &str = "GztATHHZwdAp9wwEiHIshRDi4wMZJjKq0pT5etGII3g=";

/// Computed by calling
///
/// let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
///
/// where `sk` = base64::decode(SECRET_KEY);
const PUBLIC_KEY: &str = "S+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxck";

#[test]
fn verify_single_message() {
    const SIGNATURE: &str = "i3k6l6KEdd6TtyC3FPHIfBb6nfFh3bCDYhrw3yqNkayjUTHh5Vg3aGHSJNUcwmd4MOwc65nGQmcalszpT6WTDdF3OLaQzZD5ZBufSvTVAaU89LQzQ4gqOCvDUIj3WvN78+C59zwWxM/mTCD+WkiQ5A==";
    let messages = vec![SignatureMessage::from_msg_hash(b"ExampleMessage")];

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);

    assert!(sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn no_verify_valid_signature_with_wrong_single_message() {
    const SIGNATURE: &str = "i3k6l6KEdd6TtyC3FPHIfBb6nfFh3bCDYhrw3yqNkayjUTHh5Vg3aGHSJNUcwmd4MOwc65nGQmcalszpT6WTDdF3OLaQzZD5ZBufSvTVAaU89LQzQ4gqOCvDUIj3WvN78+C59zwWxM/mTCD+WkiQ5A==";
    let messages = vec![SignatureMessage::from_msg_hash(b"BadMessage")];

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);
    assert!(!sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn verify_valid_signature_with_multiple_messages() {
    const SIGNATURE: &str  = "ige9cYZGOC+hRvQr0NpMvWru3Og+37JFgT9XQ0Z9U0W9RXAs52WebHbuFokVHgsaAm1lZ+eDAoUsf84ySvq9BEdYQyitysignwQ9zhly8bhgWnYH5TciVJVULlLml8DcMlMekv1QXExpblWpjtgJwg==";

    let messages = vec![
        SignatureMessage::from_msg_hash(b"ExampleMessage"),
        SignatureMessage::from_msg_hash(b"ExampleMessage2"),
        SignatureMessage::from_msg_hash(b"ExampleMessage3")
    ];

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);

    assert!(sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn no_verify_valid_signature_with_wrong_messages() {
    const SIGNATURE: &str  = "ige9cYZGOC+hRvQr0NpMvWru3Og+37JFgT9XQ0Z9U0W9RXAs52WebHbuFokVHgsaAm1lZ+eDAoUsf84ySvq9BEdYQyitysignwQ9zhly8bhgWnYH5TciVJVULlLml8DcMlMekv1QXExpblWpjtgJwg==";

    let messages = vec![
        SignatureMessage::from_msg_hash(b"BadMessage"),
        SignatureMessage::from_msg_hash(b"BadMessage"),
        SignatureMessage::from_msg_hash(b"BadMessage")
    ];

    let dpk = get_public_key(PUBLIC_KEY);
    let sig = get_signature(SIGNATURE);
    let dst = get_dst(DOMAIN_SEPARATION_TAG);

    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    assert!(!sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn proof_revealing_single_message_from_single_message_signature() {
    const SIGNATURE: &str = "i3k6l6KEdd6TtyC3FPHIfBb6nfFh3bCDYhrw3yqNkayjUTHh5Vg3aGHSJNUcwmd4MOwc65nGQmcalszpT6WTDdF3OLaQzZD5ZBufSvTVAaU89LQzQ4gqOCvDUIj3WvN78+C59zwWxM/mTCD+WkiQ5A==";

    let messages = vec![pm_revealed!(b"ExampleMessage")];
    let nonce = SignatureNonce::from_msg_hash(b"0123456789");

    let dpk = get_public_key(PUBLIC_KEY);
    let sig = get_signature(SIGNATURE);
    let dst = get_dst(DOMAIN_SEPARATION_TAG);

    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let pr = Verifier::new_proof_request(&[0], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_compressed_bytes();

    assert_eq!(proof_bytes.len(), 380);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"ExampleMessage")])
}

#[test]
fn proof_revealing_single_message_from_multiple_message_signature() {
    const SIGNATURE: &str  = "ige9cYZGOC+hRvQr0NpMvWru3Og+37JFgT9XQ0Z9U0W9RXAs52WebHbuFokVHgsaAm1lZ+eDAoUsf84ySvq9BEdYQyitysignwQ9zhly8bhgWnYH5TciVJVULlLml8DcMlMekv1QXExpblWpjtgJwg==";

    let messages = vec![
        pm_revealed!(b"ExampleMessage"),
        pm_hidden!(b"ExampleMessage2"),
        pm_hidden!(b"ExampleMessage3")
    ];
    let nonce = SignatureNonce::from_msg_hash(b"0123456789");

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);

    let pr = Verifier::new_proof_request(&[0], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_compressed_bytes();

    assert_eq!(proof_bytes.len(), 444);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"ExampleMessage")])
}

#[test]
fn proof_with_10_messages() {
    const SIGNATURE: &str = "jASoA+RvzeclUteE/FSymRRKAmL4IYaPDptYjRoYk2OzbHKTMQ2NMJt+C+v0veXZKHeTbmX5ALUQMQqTY7I3JyOUojIlF0gXFoBgNGN0T18SkRGKrLTdWCClphujzA6HnWKhsJiiEsjlN/wJ9blmjg==";
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

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);

    let nonce = SignatureNonce::from_msg_hash(b"0123456789");
    let pr = Verifier::new_proof_request(&[9], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_compressed_bytes();

    assert_eq!(proof_bytes.len(), 668);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"Message9")])
}

#[test]
fn proof_with_8_messages() {
    const SIGNATURE: &str = "kfNRQ42vqk1nEOJFIb6E8OZSGrJPSD9gizCxM0Ha5tDyUYbzKqjhD0eSPJdKLm7lTU8DrSDwt3WCIb72Jl9fkiQzpqyP6WULJLLBCN5oGEpYAttnymNU2aVEvaseey+6by0QW8K/J5FOy4xFz2YvRw==";

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
    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);

    let nonce = SignatureNonce::from_msg_hash(b"0123456789");
    let pr = Verifier::new_proof_request(&[0, 1, 2, 4, 6], &pk).unwrap();

    let pok = Prover::commit_signature_pok(&pr, messages.as_slice(), &sig).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_compressed_bytes();

    assert_eq!( proof_bytes.len(), 476);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    // let proved_messages = res.unwrap();
    // assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"Message9")])
}

#[ignore]
#[test]
fn print() {
    let sk = get_secret_key(SECRET_KEY);
    let dpk = get_public_key(PUBLIC_KEY);
    let dst = get_dst(DOMAIN_SEPARATION_TAG);

    let messages = vec![
        SignatureMessage::from_msg_hash(b"Message1"),
        SignatureMessage::from_msg_hash(b"Message2"),
        SignatureMessage::from_msg_hash(b"Message3"),
        SignatureMessage::from_msg_hash(b"Message4")
    ];
    let pk = dpk.to_public_key(4, dst).unwrap();
    let sig = Signature::new(messages.as_slice(), &sk, &pk).unwrap();
    println!("pk  = {}", base64::encode(&pk.to_compressed_bytes()[..]));
    println!("sig = {}", base64::encode(&sig.to_compressed_bytes()[..]));

    let nonce = SignatureNonce::from_msg_hash(b"0123456789");
    let proof_request = Verifier::new_proof_request(&[0], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        pm_revealed!(b"Message1"),
        pm_hidden!(b"Message2"),
        pm_hidden!(b"Message3"),
        pm_hidden!(b"Message4"),
    ];

    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &sig)
        .unwrap();

    // complete other zkps as desired and compute `challenge_hash`
    // add bytes from other proofs

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();
    println!("proof = {}", base64::encode(&proof.proof.to_compressed_bytes()[..]));

    let res = Verifier::verify_signature_pok(&proof_request, &proof, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();

    proof_request.revealed_messages = BTreeSet::new();
    proof_request.revealed_messages.insert(1);
    proof.revealed_messages = vec![SignatureMessage::from_msg_hash(b"Message2")];
}

fn get_dst(dst: &str) -> DomainSeparationTag {
    DomainSeparationTag::new(dst.as_bytes(), None, None, None).unwrap()
}

fn get_public_key(key: &str) -> DeterministicPublicKey {
    let dpk_bytes = base64::decode(key).unwrap();
    DeterministicPublicKey::from(*array_ref![dpk_bytes, 0, COMPRESSED_DETERMINISTIC_PUBLIC_KEY_SIZE])
}

fn get_secret_key(key: &str) -> SecretKey {
    let sk_bytes = base64::decode(key).unwrap();
    SecretKey::from(array_ref![sk_bytes, 0, COMPRESSED_SECRET_KEY_SIZE])
}

fn get_signature(sig: &str) -> Signature {
    let sig_bytes = base64::decode(sig).unwrap();
    Signature::from(*array_ref![sig_bytes, 0, COMPRESSED_SIGNATURE_SIZE])
}