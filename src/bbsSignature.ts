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

import { bls12381toBbs } from "./bls12381toBbs";
import {
  BbsBlindSignRequest,
  BbsCreateProofRequest,
  BbsSignRequest,
  BlsBbsSignRequest,
  BbsVerifyProofRequest,
  BlsBbsVerifyRequest,
  BbsVerifyRequest,
  BbsBlindSignContextRequest,
  BbsVerifyBlindSignContextRequest,
  BbsBlindSignContext,
  BbsVerifyResult,
} from "./types";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require(path.resolve(path.join(__dirname, "../native/index.node")));

/**
 * Default BBS Signature Length
 */
export const BBS_SIGNATURE_LENGTH = 112;

/**
 * Signs a set of messages with a BBS key pair and produces a BBS signature
 * @param request Request for the sign operation
 *
 * @returns The raw signature value
 */
export const sign = (request: BbsSignRequest): Uint8Array => {
  const { keyPair, messages } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return new Uint8Array(
      bbs.bbs_sign({
        publicKey: keyPair.publicKey.buffer,
        secretKey: keyPair.secretKey?.buffer as ArrayBuffer,
        messages: messageBuffers,
      })
    );
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Signs a set of messages with a BLS 12-381 key pair and produces a BBS signature
 * @param request Request for the sign operation
 *
 * @returns The raw signature value
 */
export const blsSign = (request: BlsBbsSignRequest): Uint8Array => {
  const { keyPair, messages } = request;
  const bbsKeyPair = bls12381toBbs({ keyPair, messageCount: messages.length });
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return new Uint8Array(
      bbs.bbs_sign({
        publicKey: bbsKeyPair.publicKey.buffer,
        secretKey: bbsKeyPair.secretKey?.buffer as ArrayBuffer,
        messages: messageBuffers,
      })
    );
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Verifies a BBS+ signature for a set of messages with a BBS public key
 * @param request Request for the signature verification operation
 *
 * @returns A result indicating if the signature was verified
 */
export const verify = (request: BbsVerifyRequest): BbsVerifyResult => {
  const { publicKey, signature, messages } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    const result = bbs.bbs_verify({
      publicKey: publicKey.buffer,
      signature: signature.buffer,
      messages: messageBuffers,
    });
    return { verified: result };
  } catch (ex) {
    return { verified: false, error: ex };
  }
};

/**
 * Verifies a BBS+ signature for a set of messages with a with a BLS 12-381 public key
 * @param request Request for the signature verification operation
 *
 * @returns A result indicating if the signature was verified
 */
export const blsVerify = (request: BlsBbsVerifyRequest): BbsVerifyResult => {
  try {
    const { publicKey, signature, messages } = request;
    const bbsKeyPair = bls12381toBbs({ keyPair: { publicKey }, messageCount: messages.length });
    const messageBuffers = messages.map((_) => _.buffer);
    const result = bbs.bbs_verify({
      publicKey: bbsKeyPair.publicKey.buffer,
      signature: signature.buffer,
      messages: messageBuffers,
    });
    return { verified: result };
  } catch (ex) {
    return { verified: false, error: ex };
  }
};

/**
 * Creates a BBS+ proof for a set of messages from a BBS public key and a BBS signature
 * @param request Request for the create proof operation
 *
 * @returns The raw proof value
 */
export const createProof = (request: BbsCreateProofRequest): Uint8Array => {
  const { publicKey, signature, messages, nonce, revealed } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return new Uint8Array(
      bbs.bbs_create_proof({
        nonce: nonce.buffer,
        revealed,
        publicKey: publicKey.buffer,
        signature: signature.buffer,
        messages: messageBuffers,
      })
    );
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};

/**
 * Creates a BBS+ proof for a set of messages from a BLS12-381 public key and a BBS signature
 * @param request Request for the create proof operation
 *
 * @returns The raw proof value
 */
export const blsCreateProof = (request: BbsCreateProofRequest): Uint8Array => {
  const { publicKey, signature, messages, nonce, revealed } = request;
  const bbsKeyPair = bls12381toBbs({ keyPair: { publicKey }, messageCount: messages.length });
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return new Uint8Array(
      bbs.bbs_create_proof({
        nonce: nonce.buffer,
        revealed,
        publicKey: bbsKeyPair.publicKey.buffer,
        signature: signature.buffer,
        messages: messageBuffers,
      })
    );
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};

/**
 * Verifies a BBS+ proof with a BBS public key
 * @param request Request for the verify proof operation
 *
 * @returns A result indicating if the proof was verified
 */
export const verifyProof = (request: BbsVerifyProofRequest): BbsVerifyResult => {
  const { publicKey, proof, messages, nonce } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    const result = bbs.bbs_verify_proof({
      nonce: nonce.buffer,
      publicKey: publicKey.buffer,
      proof: proof.buffer,
      messages: messageBuffers,
    });
    return { verified: result };
  } catch (ex) {
    return { verified: false, error: ex };
  }
};

/**
 * Verifies a BBS+ proof with a BLS12-381 public key
 * @param request Request for the verify proof operation
 *
 * @returns A result indicating if the proof was verified
 */
export const blsVerifyProof = (request: BbsVerifyProofRequest): BbsVerifyResult => {
  try {
    const { publicKey, proof, messages, nonce } = request;
    const messageBuffers = messages.map((_) => _.buffer);
    const result = bbs.bls_verify_proof({
      nonce: nonce.buffer,
      publicKey: publicKey.buffer,
      proof: proof.buffer,
      messages: messageBuffers,
    });
    return { verified: result };
  } catch (ex) {
    return { verified: false, error: ex };
  }
};

/**
 * Create a blinded commitment of messages for use in producing a blinded BBS+ signature
 * @param request Request for producing the blinded commitment
 *
 * @returns A commitment context
 */
export const commitmentForBlindSignRequest = (request: BbsBlindSignContextRequest): BbsBlindSignContext => {
  const { publicKey, messages, hidden, nonce } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return bbs.bbs_blind_signature_commitment({
      publicKey: publicKey.buffer,
      messages: messageBuffers,
      hidden,
      nonce,
    });
  } catch {
    throw new Error("Failed to generate commitment");
  }
};

/**
 * Verifies a blind commitment of messages
 * @param request Request for the commitment verification
 *
 * @returns A boolean indicating if the context was verified
 */
export const verifyBlindSignContext = (request: BbsVerifyBlindSignContextRequest): boolean => {
  const { commitment, proofOfHiddenMessages, challengeHash, publicKey, blinded, nonce } = request;
  return bbs.bbs_verify_blind_signature_proof({
    commitment: commitment.buffer,
    proofOfHiddenMessages: proofOfHiddenMessages.buffer,
    challengeHash: challengeHash.buffer,
    publicKey: publicKey.buffer,
    blinded,
    nonce,
  });
};

/**
 * Signs a set of messages featuring both known and blinded messages to the signer and produces a BBS+ signature
 * @param request Request for the blind sign operation
 *
 * @returns The raw signature value
 */
export const blindSign = (request: BbsBlindSignRequest): Uint8Array => {
  const { commitment, secretKey, messages } = request;
  const messageBuffers = messages.map((_) => _.buffer);
  try {
    return new Uint8Array(
      bbs.bbs_blind_sign({
        commitment: commitment.buffer,
        secretKey: secretKey.buffer,
        messages: messageBuffers,
      })
    );
  } catch (ex) {
    throw new Error("Failed to sign");
  }
};
