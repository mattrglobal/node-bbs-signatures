import { BlsKeyPair } from "./types";
// tslint:disable-next-line
const zmix = require("../native/index.node");

/**
 * Generates a BLS12-381 key pair
 */
export const generateKeyPair = (seed?: Uint8Array): BlsKeyPair => {
  const result = seed
    ? zmix.bls_generate_key(seed?.buffer)
    : zmix.bls_generate_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey)
  };
};
