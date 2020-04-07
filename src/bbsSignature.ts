import { BbsSignRequest } from "./types/BbsSignRequest";
import { BbsVerifyRequest } from "./types/BbsVerifyRequest";
// tslint:disable-next-line
const zmix = require("../native/index.node");

export const sign = (request: BbsSignRequest): Uint8Array => {
  const { domainSeperationTag, privateKey, messages } = request;
  return zmix.bbs_sign(domainSeperationTag.buffer, privateKey.buffer, messages.map(_ => _.buffer));
};

export const verify = (request: BbsVerifyRequest): boolean => {
  const { domainSeperationTag, publicKey, signature, messages } = request;
  return zmix.bbs_sign(domainSeperationTag.buffer, publicKey.buffer, signature.buffer, messages.map(_ => _.buffer));
};
