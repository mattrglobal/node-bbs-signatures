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

import { Bls12381ToBbsRequest, BbsKeyPair } from "./types";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require("../native/index.node");

/**
 * Converts a BLS12-381 key to a BBS+ key
 * @param request Request for the key conversion
 *
 * @returns A BbsKeyPair
 */
export const bls12381toBbs = (request: Bls12381ToBbsRequest): BbsKeyPair => {
  try {
    if (request.keyPair.secretKey) {
      const result = bbs.bls_secret_key_to_bbs_key({
        secretKey: request.keyPair.secretKey.buffer,
        messageCount: request.messageCount,
      });
      return {
        secretKey: request.keyPair.secretKey,
        publicKey: new Uint8Array(result),
        messageCount: request.messageCount,
      };
    } else {
      const result = bbs.bls_public_key_to_bbs_key({
        publicKey: request.keyPair.publicKey.buffer,
        messageCount: request.messageCount,
      });
      return {
        publicKey: new Uint8Array(result),
        messageCount: request.messageCount,
      };
    }
  } catch {
    throw new Error("Failed to convert key");
  }
};
