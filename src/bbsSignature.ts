import { BbsBlindSignRequest } from "./types/BbsBlindSignRequest";
import { BbsCreateProofRequest } from "./types/BbsCreateProofRequest";
import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyProofRequest } from "./types/BbsVerifyProofRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const zmix = require("../native/index.node");

/**
 * Signs a set of messages and produces a BBS signature
 */
export const sign = (request: BbsSignRequest): Uint8Array => {
  const { domainSeperationTag, secretKey, messages } = request;
  try {
    return new Uint8Array(
      zmix.bbs_sign({
        dst: domainSeperationTag,
        secretKey: secretKey.buffer as ArrayBuffer,
        messages,
      })
    );
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Signs a set of messages featuring both known and blinded messages and produces a BBS signature
 */
export const blindSign = (request: BbsBlindSignRequest): Uint8Array => {
  const { commitment, secretKey, messages, domainSeperationTag, messageCount } = request;
  try {
    return new Uint8Array(
      zmix.bbs_blind_sign({
        messageCount,
        commitment: commitment.buffer as ArrayBuffer,
        dst: domainSeperationTag,
        secretKey: secretKey.buffer as ArrayBuffer,
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
  const { domainSeperationTag, publicKey, signature, messages } = request;
  try {
    return zmix.bbs_verify({
      dst: domainSeperationTag,
      publicKey: publicKey.buffer as ArrayBuffer,
      signature: signature.buffer as ArrayBuffer,
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
  const { domainSeperationTag, publicKey, signature, messages, nonce, revealed } = request;
  try {
    return new Uint8Array(
      zmix.bbs_create_proof({
        nonce,
        revealed,
        dst: domainSeperationTag,
        publicKey: publicKey.buffer as ArrayBuffer,
        signature: signature.buffer as ArrayBuffer,
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
  const { domainSeperationTag, publicKey, proof, messages, nonce, revealed, messageCount } = request;
  try {
    return zmix.bbs_verify_proof({
      messageCount,
      nonce,
      revealed,
      dst: domainSeperationTag,
      publicKey: publicKey.buffer as ArrayBuffer,
      proof: proof.buffer as ArrayBuffer,
      messages,
    });
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};
