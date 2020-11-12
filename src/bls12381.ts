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

import { BlsKeyPair, BlindedBlsKeyPair } from "./types";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require(path.resolve(path.join(__dirname, "../native/index.node")));

/**
 * Generates a BLS12-381 key pair where the public key is a commitment in G1
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlsKeyPair
 */
export const generateBls12381G1KeyPair = async (seed?: Uint8Array): Promise<Required<BlsKeyPair>> => {
  const result = seed ? bbs.bls_generate_g1_key(seed?.buffer) : bbs.bls_generate_g1_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
  };
};

/**
 * Generates a blinded BLS12-381 key pair where the public key is a commitment in G1 to the private key
 * along with a further commitment of a blinding factor to the blinding factor generator point in G1
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlindedBlsKeyPair
 */
export const generateBlindedBls12381G1KeyPair = async (seed?: Uint8Array): Promise<Required<BlindedBlsKeyPair>> => {
  const result = seed ? bbs.bls_generate_blinded_g1_key(seed?.buffer) : bbs.bls_generate_blinded_g1_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
    blindingFactor: new Uint8Array(result.blindingFactor),
  };
};

/**
 * Generates a BLS12-381 key pair where the public key is a commitment in G2
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlsKeyPair
 */
export const generateBls12381G2KeyPair = async (seed?: Uint8Array): Promise<Required<BlsKeyPair>> => {
  const result = seed ? bbs.bls_generate_g2_key(seed?.buffer) : bbs.bls_generate_g2_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
  };
};

/**
 * Generates a blinded BLS12-381 key pair where the public key is a commitment in G2 to the private key
 * along with a further commitment of a blinding factor to the blinding factor generator point in G2
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlindedBlsKeyPair
 */
export const generateBlindedBls12381G2KeyPair = async (seed?: Uint8Array): Promise<Required<BlindedBlsKeyPair>> => {
  const result = seed ? bbs.bls_generate_blinded_g2_key(seed?.buffer) : bbs.bls_generate_blinded_g2_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
    blindingFactor: new Uint8Array(result.blindingFactor),
  };
};
