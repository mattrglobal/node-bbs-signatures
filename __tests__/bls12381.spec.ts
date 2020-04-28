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
import {
  generateBls12381KeyPair,
  DEFAULT_BLS12381_PUBLIC_KEY_LENGTH,
  DEFAULT_BLS12381_PRIVATE_KEY_LENGTH,
} from "../src";

describe("bls12381", () => {
  it("should be able to generate a key pair", () => {
    const result = generateBls12381KeyPair();
    expect(result).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey?.length as number).toEqual(DEFAULT_BLS12381_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_BLS12381_PUBLIC_KEY_LENGTH);
  });

  it("should be able to generate a key pair with a seed", () => {
    const result = generateBls12381KeyPair(
      new Uint8Array(new Buffer("H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=", "base64"))
    );
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey?.length as number).toEqual(DEFAULT_BLS12381_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_BLS12381_PUBLIC_KEY_LENGTH);
    expect(result.publicKey).toEqual(
      new Uint8Array(
        new Buffer(
          "ha+sckj0C+dXR6IPUfxGJMCc3XHkGgoDz2PHPMVrMMhJXSGO5y7VrAHrZt64MThKGXE+SAOTHFS5jGoP5uHWvhabYHuIlHLpZHiLyg2m4sc6yfMG3tloUxLY+TiaeQCG",
          "base64"
        )
      )
    );
    expect(result.secretKey as Uint8Array).toEqual(
      new Uint8Array(new Buffer("Ovy0NyLx6ET9/AkuSmxw7X3IGMRq4IqrmFRfzWf/QvQ=", "base64"))
    );
  });
});
