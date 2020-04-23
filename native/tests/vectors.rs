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
// const SECRET_KEY: &str = "AAAAAAAAAAAAAAAAAAAAABs7QExx2cHQKfcMBIhyLIUQ4uMDGSYyqtKU+XrRiCN4";

/// Computed by calling
///
/// let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
///
/// where `sk` = base64::decode(SECRET_KEY);
const PUBLIC_KEY: &str = "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t";

#[test]
fn verify_single_message() {
    const SIGNATURE: &str = "BAN3Hm/9F8dmVJE7yYJkQz6XIH1Am454LBXjU5kEcRrX4xYZ7f9+ztqkSRr5BD56IBPRXngoo2u14UqJwSr/lgbF7bw1AIdUX+Ipnez9Y/eh466QaymKBCdFdkjXBKakRQAAAAAAAAAAAAAAAAAAAABxjP0o2lcC86xG3shFMloCBh4Bn3jh4UW3foRkalSglgAAAAAAAAAAAAAAAAAAAABnJvxeDnd0vNLpOw8z6Gu1cpvQG01ptYeORAIHYmJ/ug==";
    let messages = vec![SignatureMessage::from_msg_hash(b"ExampleMessage")];

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);
    assert!(sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn no_verify_valid_signature_with_wrong_single_message() {
    const SIGNATURE: &str = "BAN3Hm/9F8dmVJE7yYJkQz6XIH1Am454LBXjU5kEcRrX4xYZ7f9+ztqkSRr5BD56IBPRXngoo2u14UqJwSr/lgbF7bw1AIdUX+Ipnez9Y/eh466QaymKBCdFdkjXBKakRQAAAAAAAAAAAAAAAAAAAABxjP0o2lcC86xG3shFMloCBh4Bn3jh4UW3foRkalSglgAAAAAAAAAAAAAAAAAAAABnJvxeDnd0vNLpOw8z6Gu1cpvQG01ptYeORAIHYmJ/ug==";
    let messages = vec![SignatureMessage::from_msg_hash(b"BadMessage")];

    let dst = get_dst(DOMAIN_SEPARATION_TAG);
    let dpk = get_public_key(PUBLIC_KEY);
    let pk = dpk.to_public_key(messages.len(), dst).unwrap();
    let sig = get_signature(SIGNATURE);
    assert!(!sig.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn verify_valid_signature_with_multiple_messages() {
    const SIGNATURE: &str  = "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw==";

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
    const SIGNATURE: &str  = "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw==";

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
    const SIGNATURE: &str = "BAN3Hm/9F8dmVJE7yYJkQz6XIH1Am454LBXjU5kEcRrX4xYZ7f9+ztqkSRr5BD56IBPRXngoo2u14UqJwSr/lgbF7bw1AIdUX+Ipnez9Y/eh466QaymKBCdFdkjXBKakRQAAAAAAAAAAAAAAAAAAAABxjP0o2lcC86xG3shFMloCBh4Bn3jh4UW3foRkalSglgAAAAAAAAAAAAAAAAAAAABnJvxeDnd0vNLpOw8z6Gu1cpvQG01ptYeORAIHYmJ/ug==";

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
    challenge_bytes.extend_from_slice(nonce.to_bytes().as_slice());

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes();

    assert_eq!(proof_bytes.len(), 693);
    println!("proof = {}", base64::encode(proof_bytes));

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"ExampleMessage")])
}

#[test]
fn proof_revealing_single_message_from_multiple_message_signature() {
    const SIGNATURE: &str  = "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw==";

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
    challenge_bytes.extend_from_slice(nonce.to_bytes().as_slice());

    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);

    let sig_pok = Prover::generate_signature_pok(pok, &challenge).unwrap();

    let proof_bytes = sig_pok.proof.to_bytes();

    println!("proof_bytes = {}", base64::encode(&proof_bytes));
    assert_eq!(proof_bytes.len(), 789);

    let res = Verifier::verify_signature_pok(&pr, &sig_pok, &nonce);

    assert!(res.is_ok());
    let proved_messages = res.unwrap();
    assert_eq!(proved_messages, vec![SignatureMessage::from_msg_hash(b"ExampleMessage")])
}


fn get_dst(dst: &str) -> DomainSeparationTag {
    DomainSeparationTag::new(dst.as_bytes(), None, None, None).unwrap()
}

fn get_public_key(key: &str) -> DeterministicPublicKey {
    let dpk_bytes = base64::decode(key).unwrap();
    DeterministicPublicKey::from_bytes(*array_ref![dpk_bytes, 0, PUBLIC_KEY_SIZE])
}

// fn get_secret_key(key: &str) -> SecretKey {
//     let sk_bytes = base64::decode(key).unwrap();
//     SecretKey::from_bytes(&sk_bytes).unwrap()
// }

fn get_signature(sig: &str) -> Signature {
    let sig_bytes = base64::decode(sig).unwrap();
    Signature::from_bytes(*array_ref![sig_bytes, 0, SIGNATURE_SIZE])
}