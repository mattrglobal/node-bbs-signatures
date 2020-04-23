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
import { sign, verify, createProof, verifyProof } from "../src/bbsSignature";
import { Coder } from "@stablelib/base64";
import { generateSignRequest } from "./helper";

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

const nonce = "mynonce";

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


// define verify routine
const run_benchmark = (numberOfMessages: number, messageSizeInBytes: number, numberRevealed: number) => {
  const MessageSignRequest = generateSignRequest(blsKeyPair.secretKey, domainSeparationTag, 1, 100);
  const MessageSignature = sign(MessageSignRequest);
  const MessageVerifyRequest = {
    signature: MessageSignature,
    publicKey: blsKeyPair.publicKey,
    domainSeparationTag,
    messages: MessageSignRequest.messages,
  };
  
  report(
    `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    benchmark(() => sign(MessageSignRequest))
  );
  
  report(
    `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    benchmark(() => verify(MessageVerifyRequest))
  );
  
  const revealed_numbers = [...Array(numberRevealed).keys()];

  const CreateProofRequest = {
    signature: MessageSignature,
    publicKey: blsKeyPair.publicKey,
    messages: MessageSignRequest.messages,
    revealed: revealed_numbers,
    nonce,
    domainSeparationTag,
  };
  
  const MessageProof = createProof(CreateProofRequest);
  
  const VerifyProofRequest = {
    proof: MessageProof,
    publicKey: blsKeyPair.publicKey,
    messages: MessageSignRequest.messages.slice(0, numberRevealed),
    revealed: revealed_numbers,
    messageCount: MessageSignRequest.messages.length,
    nonce,
    domainSeparationTag
  };
  
  report(
    `BBS Create Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
    benchmark(() => createProof(CreateProofRequest))
  );
  
  report(
    `BBS Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
    benchmark(() => verifyProof(VerifyProofRequest))
  );
};


// ------------------------------ Sign/Verify 1, 100 byte message ------------------------------
run_benchmark(1, 100, 1);
// ---------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 1, 1000 byte message ------------------------------
run_benchmark(1, 1000, 1);
// ---------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 10, 100 byte messages ------------------------------
run_benchmark(10, 100, 1);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 10, 1000 byte messages ------------------------------
run_benchmark(10, 1000, 1);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 100, 100 byte messages ------------------------------
run_benchmark(100, 100, 1);
// -----------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify 100, 1000 byte messages ------------------------------
run_benchmark(100, 1000, 1);
// -----------------------------------------------------------------------------------------------
