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

import { randomBytes } from "@stablelib/random";
import { generateBls12381KeyPair, DEFAULT_PUBLIC_KEY_LENGTH, DEFAULT_PRIVATE_KEY_LENGTH } from "../src";

describe("bls12381", () => {
  it("should be able to generate a key pair", () => {
    const result = generateBls12381KeyPair();
    expect(result).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey.length).toEqual(DEFAULT_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH);
  });

  it("should be able to generate a key pair with a seed", () => {
    const seed = randomBytes(50);
    const result = generateBls12381KeyPair(seed);
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey.length).toEqual(DEFAULT_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH);
  });
});
