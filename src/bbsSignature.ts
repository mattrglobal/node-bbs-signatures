import { BbsBlindSignRequest } from "./types/BbsBlindSignRequest";
import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";
import { BbsBlindSignRequest } from "./types/BbsBlindSignRequest";
// tslint:disable-next-line
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
        messages
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
  const {
    commitment,
    secretKey,
    messages,
    domainSeperationTag,
    messageCount
  } = request;
  try {
    return new Uint8Array(
      zmix.bbs_blind_sign({
        messageCount,
        commitment: commitment.buffer as ArrayBuffer,
        dst: domainSeperationTag,
        secretKey: secretKey.buffer as ArrayBuffer,
        messages
      })
    );
  } catch (ex) {
    throw new Error("Failed to sign");
  }
};

/**
 * Signs a set of messages featuring both known and blinded messages and produces a BBS signature
 */
export const blindSign = (request: BbsBlindSignRequest): Uint8Array => {
  const { commitment, secretKey, messages, domainSeperationTag, messageCount } = request;
  try {
    return new Uint8Array(zmix.bbs_blind_sign({ messageCount, commitment : commitment.buffer as ArrayBuffer, dst: domainSeperationTag, secretKey: secretKey.buffer as ArrayBuffer, messages}));
  }
  catch(ex) {
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
      messages
    });
  } catch {
    throw new Error("Failed to verify");
  }
};
