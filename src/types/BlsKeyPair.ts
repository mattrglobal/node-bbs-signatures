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

/**
 * Default BLS 12-381 private key length
 */
export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

/**
 * Default BLS 12-381 public key length in G2 field
 */
export const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

/**
 * Default BLS 12-381 public key length in G2 field
 */
export const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

/**
 * Length of the blinding factor for BLS 12-381 keys
 */
export const BLS12381_BLINDING_FACTOR_LENGTH = 32;

/**
 * A BLS 12-381 key pair
 */
export interface BlsKeyPair {
  /**
   * Raw public key value for the key pair
   */
  readonly publicKey: Uint8Array;
  /**
   * Raw secret/private key value for the key pair
   */
  readonly secretKey?: Uint8Array;
}
/**
 * A Blinded BLS 12-381 key pair
 */
export interface BlindedBlsKeyPair {
  /**
   * Raw public key value for the key pair
   */
  readonly publicKey: Uint8Array;
  /**
   * Raw secret/private key value for the key pair
   */
  readonly secretKey?: Uint8Array;
  /**
   * Blinding factor
   */
  readonly blindingFactor: Uint8Array;
}
