import { BlsKeyPair } from "./types";
const zmix = require("../native/index.node");

export const generateKeyPair = (): BlsKeyPair => {
  const result = zmix.bls_generate_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey)
  };
};
