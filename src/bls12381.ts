import { BlsKeyPair } from "./types";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const zmix = require("../native/index.node");

/**
 * Private key length
 */
export const DEFAULT_PRIVATE_KEY_LENGTH = 48;

/**
 * Public key length
 */
export const DEFAULT_PUBLIC_KEY_LENGTH = 192;

/**
 * Generates a BLS12-381 key pair
 */
export const generateKeyPair = (seed?: Uint8Array): BlsKeyPair => {
  const result = seed ? zmix.bls_generate_key(seed?.buffer) : zmix.bls_generate_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
  };
};
