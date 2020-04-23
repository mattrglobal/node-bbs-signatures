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

/* eslint-disable @typescript-eslint/camelcase */
import { benchmark, report } from "@stablelib/benchmark";
import { generateBls12381KeyPair } from "../src/bls12381";
import { sign, verify } from "../src/bbsSignature";
import { Coder } from "@stablelib/base64";
import { generateSignRequest } from "./helper";

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

const domainSeparationTag = "BBSSignature2020";
const blsKeyPair = {
  secretKey: base64Decode("AAAAAAAAAAAAAAAAAAAAAFutvcqd+rMKit2/lHuUBrarW0MQHYXEhdwRiDAWF6xU"),
  publicKey: base64Decode(
    "BTOwo3q9pwqyCJA7H14HCg21e/gB079teu1asBO15o4q25t2cRFEwjDdTxly9na3Fqio+vkgftdPROoQR5PRBvkbOksEEuqROwdDw9d32LqUx2yEEhKnBialXfkv/XPACJNdDzy8dPFCXq2kQI1FdsNRWpSFGdbMXIwwNgu6lLRtkJLd7U2ODwqjlC76XaGUA+svFUnaG46CpOidVMkZeVlhwwG4NlCdeVrX4oczdY5nuXHzx0Utxc3KmNgiJoKT"
  ),
};

report(
  "BLS 12-381 Key Generation",
  benchmark(() => generateBls12381KeyPair())
);

// ------------------------------ Sign/Verify 1000, 100 byte messages ------------------------------
const thousand_HundredByteMessageSignRequest = generateSignRequest(
  blsKeyPair.secretKey,
  domainSeparationTag,
  1000,
  100
);
const thousand_HundredByteMessageSignature = sign(thousand_HundredByteMessageSignRequest);
const thousand_HundredByteMessageVerifyRequest = {
  signature: thousand_HundredByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: thousand_HundredByteMessageSignRequest.messages,
};

report(
  "BBS Sign 1000, 100 byte messages",
  benchmark(() => sign(thousand_HundredByteMessageSignRequest))
);

report(
  "BBS Verify 1000, 100 byte messages",
  benchmark(() => verify(thousand_HundredByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 1000, 1000 byte messages ------------------------------
const thousand_ThousandByteMessageSignRequest = generateSignRequest(
  blsKeyPair.secretKey,
  domainSeparationTag,
  1000,
  100
);
const thousand_ThousandByteMessageSignature = sign(thousand_HundredByteMessageSignRequest);
const thousand_ThousandByteMessageVerifyRequest = {
  signature: thousand_ThousandByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: thousand_ThousandByteMessageSignRequest.messages,
};

report(
  "BBS Sign 1000, 1000 byte messages",
  benchmark(() => sign(thousand_ThousandByteMessageSignRequest))
);

report(
  "BBS Verify 1000, 1000 byte messages",
  benchmark(() => verify(thousand_ThousandByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------
