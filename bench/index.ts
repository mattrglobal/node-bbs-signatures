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

// ------------------------------ Sign/Verify 1, 100 byte message ------------------------------
const one_HundredByteMessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 1, 100);
const one_HundredByteMessageSignature = sign(one_HundredByteMessageSignRequest);
const one_HundredByteMessageVerifyRequest = {
  signature: one_HundredByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: one_HundredByteMessageSignRequest.messages,
};

report(
  "BBS Sign 1, 100 byte message",
  benchmark(() => sign(one_HundredByteMessageSignRequest))
);

report(
  "BBS Verify 1, 100 byte message",
  benchmark(() => verify(one_HundredByteMessageVerifyRequest))
);
// ---------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 1, 1000 byte message ------------------------------
const one_ThousandByteMessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 1, 1000);
const one_ThousandByteMessageSignature = sign(one_HundredByteMessageSignRequest);
const one_ThousandByteMessageVerifyRequest = {
  signature: one_ThousandByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: one_ThousandByteMessageSignRequest.messages,
};

report(
  "BBS Sign 1, 1000 byte message",
  benchmark(() => sign(one_ThousandByteMessageSignRequest))
);

report(
  "BBS Verify 1, 1000 byte message",
  benchmark(() => verify(one_ThousandByteMessageVerifyRequest))
);
// ---------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 10, 100 byte messages ------------------------------
const ten_HundredByteMessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 10, 100);
const ten_HundredByteMessageSignature = sign(ten_HundredByteMessageSignRequest);
const ten_HundredByteMessageVerifyRequest = {
  signature: ten_HundredByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: ten_HundredByteMessageSignRequest.messages,
};

report(
  "BBS Sign 10, 100 byte messages",
  benchmark(() => sign(ten_HundredByteMessageSignRequest))
);

report(
  "BBS Verify 10, 100 byte messages",
  benchmark(() => verify(ten_HundredByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 10, 1000 byte messages ------------------------------
const ten_ThousandByteMessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 10, 1000);
const ten_ThousandByteMessageSignature = sign(ten_HundredByteMessageSignRequest);
const ten_ThousandByteMessageVerifyRequest = {
  signature: ten_ThousandByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: ten_ThousandByteMessageSignRequest.messages,
};

report(
  "BBS Sign 10, 1000 byte messages",
  benchmark(() => sign(ten_ThousandByteMessageSignRequest))
);

report(
  "BBS Verify 10, 1000 byte messages",
  benchmark(() => verify(ten_ThousandByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 100, 100 byte messages ------------------------------
const hundred_HundredByteMessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 100, 100);
const hundred_HundredByteMessageSignature = sign(hundred_HundredByteMessageSignRequest);
const hundred_HundredByteMessageVerifyRequest = {
  signature: hundred_HundredByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: hundred_HundredByteMessageSignRequest.messages,
};

report(
  "BBS Sign 100, 100 byte messages",
  benchmark(() => sign(hundred_HundredByteMessageSignRequest))
);

report(
  "BBS Verify 100, 100 byte messages",
  benchmark(() => verify(hundred_HundredByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 100, 100 byte messages ------------------------------
const hundred_ThousandByteMessageSignRequest = generateSignRequest(
  blsKeyPair.secretKey,
  domainSeparationTag,
  100,
  1000
);
const hundred_ThousandByteMessageSignature = sign(hundred_HundredByteMessageSignRequest);
const hundred_ThousandByteMessageVerifyRequest = {
  signature: hundred_ThousandByteMessageSignature,
  publicKey: blsKeyPair.publicKey,
  domainSeparationTag,
  messages: hundred_ThousandByteMessageSignRequest.messages,
};

report(
  "BBS Sign 100, 1000 byte messages",
  benchmark(() => sign(hundred_ThousandByteMessageSignRequest))
);

report(
  "BBS Verify 100, 1000 byte messages",
  benchmark(() => verify(hundred_ThousandByteMessageVerifyRequest))
);
// -----------------------------------------------------------------------------------------------
