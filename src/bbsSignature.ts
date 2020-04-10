import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";
// tslint:disable-next-line
const zmix = require("../native/index.node");

/**
 * Signs a set of messages and produces a BBS signature
 */
export const sign = (request: BbsSignRequest): Uint8Array => {
  const { domainSeperationTag, secretKey, messages } = request;
  try {
    return new Uint8Array(zmix.bbs_sign({ dst: domainSeperationTag, secretKey: secretKey.buffer as ArrayBuffer, messages}));
  }
  catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Verifies a BBS signature for a set of messages
 */
export const verify = (request: BbsVerifyRequest): boolean => {
  const { domainSeperationTag, publicKey, signature, messages } = request;
  try {
    return zmix.bbs_verify({ dst: domainSeperationTag, publicKey: publicKey.buffer as ArrayBuffer, signature: signature.buffer as ArrayBuffer, messages});
  }
  catch {
    throw new Error("Failed to verify");
  }
};
