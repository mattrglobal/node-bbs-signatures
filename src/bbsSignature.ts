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

import { BbsBlindSignRequest } from "./types/BbsBlindSignRequest";
import { BbsCreateProofRequest } from "./types/BbsCreateProofRequest";
import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyProofRequest } from "./types/BbsVerifyProofRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";
import { BbsBlindSignContextRequest } from "./types/BbsBlindSignContextRequest";
import { BbsBlindSignContext } from "./types/BbsBlindSignContext";
import { BbsVerifyBlindSignContextRequest } from "./types/BbsVerifyBlindSignContextRequest";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const zmix = require("../native/index.node");

/**
 * Signs a set of messages and produces a BBS signature
 */
export const sign = (request: BbsSignRequest): Uint8Array => {
  const { publicKey, secretKey, messages } = request;
  try {
    return new Uint8Array(
      zmix.bbs_sign({
        publicKey: publicKey.buffer,
        secretKey: secretKey.buffer,
        messages,
      })
    );
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Create a blind signing context for where some messages are blinded to produce a BBS+ signature
 */
export const commitmentForBlindSignRequest = (request: BbsBlindSignContextRequest): BbsBlindSignContext => {
    const { publicKey, messages, hidden, nonce } = request;
    try {
        return zmix.bbs_blind_signature_commitment({
            publicKey: publicKey.buffer,
            messages,
            hidden,
            nonce
        });
    } catch {
        throw new Error("Failed to generate commitment");
    }
}

export const verifyBlindSignContext = (request: BbsVerifyBlindSignContextRequest): boolean => {
    const { commitment, proofOfHiddenMessages, challengeHash, publicKey, blinded, nonce } = request;
    return zmix.bbs_verify_blind_signature_proof({
        commitment: commitment.buffer,
        proofOfHiddenMessages: proofOfHiddenMessages.buffer,
        challengeHash: challengeHash.buffer,
        publicKey: publicKey.buffer,
        blinded,
        nonce
    });
}

/**
 * Signs a set of messages featuring both known and blinded messages and produces a BBS+ signature
 */
export const blindSign = (request: BbsBlindSignRequest): Uint8Array => {
  const { commitment, secretKey, messages } = request;
  try {
    return new Uint8Array(
      zmix.bbs_blind_sign({
        commitment: commitment.buffer,
        secretKey: secretKey.buffer,
        messages,
      })
    );
  } catch (ex) {
    throw new Error("Failed to sign");
  }
};

/**
 * Verifies a BBS signature for a set of messages
 */
export const verify = (request: BbsVerifyRequest): boolean => {
  const { publicKey, signature, messages } = request;
  try {
    return zmix.bbs_verify({
      publicKey: publicKey.buffer,
      signature: signature.buffer,
      messages,
    });
  } catch {
    throw new Error("Failed to verify");
  }
};

/**
 * Creates a BBS proof for a set of messages from a BBS signature
 */
export const createProof = (request: BbsCreateProofRequest): Uint8Array => {
  const { domainSeparationTag, publicKey, signature, messages, nonce, revealed } = request;
  try {
    return new Uint8Array(
      zmix.bbs_create_proof({
        nonce,
        revealed,
        dst: domainSeparationTag,
        publicKey: publicKey.buffer,
        signature: signature.buffer,
        messages,
      })
    );
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};

/**
 * Verifies a BBS proof
 */
export const verifyProof = (request: BbsVerifyProofRequest): Uint8Array => {
  const { domainSeparationTag, publicKey, proof, messages, nonce, revealed, messageCount } = request;
  try {
    return zmix.bbs_verify_proof({
      messageCount,
      nonce,
      revealed,
      dst: domainSeparationTag,
      publicKey: publicKey.buffer,
      proof: proof.buffer,
      messages,
    });
  } catch (ex) {
    throw new Error("Failed to verify proof");
  }
};
