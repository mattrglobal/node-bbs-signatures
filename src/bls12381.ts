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

import { BlsKeyPair } from "./types";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require("../native/index.node");

/**
 * Generates a BLS12-381 key pair
 * @param seed [Optional] To derive the key pair from
 * 
 * @returns A BlsKeyPair
 */
export const generateBls12381KeyPair = (seed?: Uint8Array): BlsKeyPair => {
  const result = seed ? bbs.bls_generate_key(seed?.buffer) : bbs.bls_generate_key();
  return {
    publicKey: new Uint8Array(result.publicKey),
    secretKey: new Uint8Array(result.secretKey),
  };
};

