import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";
// tslint:disable-next-line
const zmix = require("../native/index.node");

/**
 * Signs a set of messages and produces a BBS signature
 */
export const sign = (request: BbsSignRequest): Uint8Array => {
  const { domainSeperationTag, secretKey, messages } = request;
  return zmix.bbs_sign({ dst: domainSeperationTag, secretKey: secretKey.buffer as ArrayBuffer, messages});
};

/**
 * Verifies a BBS signature for a set of messages
 */
export const verify = (request: BbsVerifyRequest): boolean => {
  const { domainSeperationTag, publicKey, signature, messages } = request;
  return zmix.bbs_verify({ dst: domainSeperationTag, publicKey, signature: signature.buffer, messages});
};
