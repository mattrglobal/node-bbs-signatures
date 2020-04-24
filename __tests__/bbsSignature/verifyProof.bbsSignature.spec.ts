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

import {
  BbsVerifyProofRequest,
  BbsCreateProofRequest,
} from "../../src";
import { Coder } from "@stablelib/base64";
import { createProof, verifyProof } from "../../src/bbsSignature";

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  describe("verifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", () => {
      const messages = ["ExampleMessage"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const proof = base64Decode(
        "BBOUeuTlS8OBW7Wdi4y1gw19RhWGiTrHZxkrsKxbVsSV4R3bnJPxRfTEKPppL6+l3wdSJytilegXS+LY1zp9IMWq1yFFTjMs+VJ1nOV8ByuaqIAi8iaWYZkV0D+7F+Dd/wQSqDcUUgom/z9gjd0ccGxAyY3Xp0fvUMVC4df0wq8LEaUoUlJ6KveVdKhdyjM8JpUL91lU6xIDKgdUoPXXrmwvl3+A7FyD87mHYWpft1TZwS2z02Pm+Vrtlj59AlA1UWMEEmIxdc/vZ2A8XqnaJxFifjn/elonOyHqzPqczf8EnpQ0WsNlBRf2RtNCL3Pdbg1qGX8KVC4LykweUysb32oFaLmzTNcCf1wQRebF8ThYkw1Ir743YShY1E0rkoHrXaGHAAAAxQQFHzlXG7EzlM78qQsHVQETl0qTTh1K7bx/fV8k2QOyAIrrYwSGHyY/Du0/CQpO+4UXzyvK49xoiCKK98VZwznE6+i5EoHvMPHAvwTYCeQ2O7AnXrde1bhXVChfjmV7sVsAAAACAAAAAAAAAAAAAAAAAAAAAGsJd/MjlKzVVifZeg0flq/miDGmVCSt4uJcH0ipCJRDAAAAAAAAAAAAAAAAAAAAAAFcp5VQq5Ky2+VxaW/dB/d4c2xHMYWHIiIYcCfrZBVUAAAAxQQQREgS3nJPUKSqJ6LA0tKzTbBcPq5ZOdT0NaSUhsrzFs+4P9arvXjBcW4doDyHxiIHeAs5cFOakHqNOWt+sRPBtpHYYcFcG35SiY7A8v62YELFpNl7zIucAEd/PMzpZLAAAAACAAAAAAAAAAAAAAAAAAAAAGt7rKl/L0lDyM7qS2PgGe/z2DP6IxW7RlSDB59VkwMfAAAAAAAAAAAAAAAAAAAAABGHKGYJgLhfW96kt+QVZFS4y9vKZFvJ8l6/eeGksSxl"
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 1,
        messages,
        nonce: "0123456789",
        revealed: [0],
      };

      expect(verifyProof(request)).toBeTruthy();
    });

    it("should verify proof with one message revealed from multi-message signature", () => {
      const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const proof = base64Decode(
        "BBcvpNLj52ME8tTYY/9ZLFxblirPDUbjBEYnvlW+LbsPpaqMKpP0UOvCUZHICFxHhw6cLk4LWmtJWb56A+NVCWeFxhEnxcRPFgQHuMDeGNh16ZBLUYna/Tr9hLtdq/jLnwQODZ3nWiECM5IbVlRkvdSwlWDvF44ChKShKGYhcgRDwzrsyCwAZUx1f2hHk5P77CIXL5WSWnYA1QgZgANejcQDZopc9qSg301C846ly1dblO3ATvvCVSxWSrQ7lNn60bgEC4BuV1jmm3FyefUUU4+K5KMzsvmC5eyCnHWb5ier/bY9XiOsaFJUjRBeleiPk24HD56tagnT9TIBGFxzGEgAKTeupZpfztebZ8pZIXxbos91yk+AhCpwlHbj0YZ/qFo3AAAAxQQDNlDRKedeZYb3s2eek1cKiQx4abjUIDO5RK08Ci7vhe6c75GnXUbdl3mUbMyncJIVrSSF5Iu+bwZ7nE7vJXyBbPP7eivvZmcZY6knSC5BGHL2RyV0KdImlggVeefHe5YAAAACAAAAAAAAAAAAAAAAAAAAAAAtR8hRwtFJwbcocjK/AogO/ceEwp2bhKDqQIz7R4uXAAAAAAAAAAAAAAAAAAAAAFpcdqyDmqgmBqaZA5Su3ayZMx4We3qpVpnnGZqzjdEsAAABJQQRVFXS3jwEsJwKEcOvSLULUc2/8UhXezdUMzwkb/G9AKVjzIhukg0qKOBbhpgG/jwC8ejyvNLmP1qyfpqr0ENejILV1Cw+CrZHTezCjFiJk19Uj3k8rur48egYU8bnOcgAAAAEAAAAAAAAAAAAAAAAAAAAADpdXCCsTOUwnFH3awq7B7pbPDmiNqbr+xifhrM5d7PAAAAAAAAAAAAAAAAAAAAAACmxsy4qXuoUbR9ABk1mW7+AsyRJTsaCuZ7WEXTEE3mZAAAAAAAAAAAAAAAAAAAAACDIZmi5klvGnKmsO50e4aFBlJqkAFOjirVz8uB5Erl2AAAAAAAAAAAAAAAAAAAAAAwa5eqxMFCr+JbwUUgQtfcmSfb09ylCv1CtLs0nncu/"
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 3,
        messages,
        nonce: "0123456789",
        revealed: [0],
      };

      expect(verifyProof(request)).toBeTruthy();
    });
  });

  describe("create and verify proofs", () => {
    it("create and verify proof with all messages revealed from multi-message signature", () => {
      const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const signature = base64Decode(
        "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey,
        messages,
        nonce: "0123456789",
        revealed: [0, 1, 2],
      };
      const proof = createProof(request);

      const response: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 3,
        messages,
        nonce: "0123456789",
        revealed: [0, 1, 2],
      };
      expect(verifyProof(response)).toBeTruthy();
    });

    it("create and verify proof with no messages revealed from multi-message signature", () => {
      const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const signature = base64Decode(
        "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey,
        messages,
        nonce: "0123456789",
        revealed: [],
      };
      const proof = createProof(request);

      const response: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 3,
        messages: [],
        nonce: "0123456789",
        revealed: [],
      };
      expect(verifyProof(response)).toBeTruthy();
    });
  });
});
