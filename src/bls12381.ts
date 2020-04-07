import { BlsKeyPair } from "./types";
const zmix = require("../native/index.node");

export const generateKeyPair = (seed?: Uint8Array): BlsKeyPair => {
  const result = seed ? zmix.bls_generate_key(seed?.buffer) : zmix.bls_generate_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey)
  };
};

