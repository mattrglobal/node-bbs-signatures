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
import { generateSignRequest } from "./helper";
import { bls12381toBbs } from "../src";

const nonce = "mynonce";

report(
  "BLS 12-381 Key Generation",
  benchmark(() => generateBls12381KeyPair())
);

// main benchmark routine
const run_benchmark = (numberOfMessages: number, messageSizeInBytes: number, numberRevealed: number): void => {
  const blsKeyPair = generateBls12381KeyPair();
  const bbsKeyPair = bls12381toBbs({ keyPair: blsKeyPair, messageCount: numberOfMessages });
  const MessageSignRequest = generateSignRequest(bbsKeyPair, numberOfMessages, messageSizeInBytes);
  const MessageSignature = sign(MessageSignRequest);
  const MessageVerifyRequest = {
    signature: MessageSignature,
    publicKey: bbsKeyPair.publicKey,
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

  const revealedNumbers = [...Array(numberRevealed).keys()];

  const CreateProofRequest = {
    signature: MessageSignature,
    publicKey: bbsKeyPair.publicKey,
    messages: MessageSignRequest.messages,
    revealed: revealedNumbers,
    nonce,
  };

  const MessageProof = createProof(CreateProofRequest);

  const VerifyProofRequest = {
    proof: MessageProof,
    publicKey: bbsKeyPair.publicKey,
    messages: MessageSignRequest.messages.slice(0, numberRevealed),
    revealed: revealedNumbers,
    messageCount: MessageSignRequest.messages.length,
    nonce,
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

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 100 byte message ------------------------------
run_benchmark(1, 100, 1);
// ---------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 1000 byte message ------------------------------
run_benchmark(1, 1000, 1);
// ----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 100 byte messages ------------------------------
run_benchmark(10, 100, 1);
// -----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 1000 byte messages ------------------------------
run_benchmark(10, 1000, 1);
// ------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
run_benchmark(100, 100, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
run_benchmark(100, 1000, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
run_benchmark(100, 100, 50);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
run_benchmark(100, 1000, 60);
// -------------------------------------------------------------------------------------------------------------------------
