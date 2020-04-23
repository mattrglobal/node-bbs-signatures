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

import { BlsToBbsRequest, BbsKeyPair } from "./types";
import { DEFAULT_PRIVATE_KEY_LENGTH } from "./bls12381";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const zmix = require("../native/index.node");

/**
 * Convert a BLS key to a BBS+ key
 */
export const getBbsPublicKey = (request: BlsToBbsRequest): BbsKeyPair => {
    if (request.blsKey.byteLength == DEFAULT_PRIVATE_KEY_LENGTH) {
        let result = zmix.bls_secret_key_to_bbs_key(request);
        return {
            publicKey: result,
            messageCount: request.messageCount,
            secretKey: request.blsKey
        };
    } else {
        let result = zmix.bls_public_key_to_bbs_key(request);
        return {
            publicKey: result,
            messageCount: request.messageCount,
        };
    }
}
