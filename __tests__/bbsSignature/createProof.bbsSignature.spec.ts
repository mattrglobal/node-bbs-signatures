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
    generateBls12381KeyPair,
    BbsCreateProofRequest,
    createProof,
  } from "../../src";
import { Coder } from "@stablelib/base64";
import { randomBytes } from "crypto";

  const base64Encode = (bytes: Uint8Array): string => {
    const coder = new Coder();
    return coder.encode(bytes);
  };
  
  const base64Decode = (string: string): Uint8Array => {
    const coder = new Coder();
    return coder.decode(string);
  };
  
  describe("bbsSignature", () => {
    describe("createProof", () => {
      it("should create proof revealing single message from single message signature", () => {
        const messages = ["ExampleMessage"];
        const publicKey = base64Decode(
          "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
        );
        const signature = base64Decode(
          "BAN3Hm/9F8dmVJE7yYJkQz6XIH1Am454LBXjU5kEcRrX4xYZ7f9+ztqkSRr5BD56IBPRXngoo2u14UqJwSr/lgbF7bw1AIdUX+Ipnez9Y/eh466QaymKBCdFdkjXBKakRQAAAAAAAAAAAAAAAAAAAABxjP0o2lcC86xG3shFMloCBh4Bn3jh4UW3foRkalSglgAAAAAAAAAAAAAAAAAAAABnJvxeDnd0vNLpOw8z6Gu1cpvQG01ptYeORAIHYmJ/ug=="
        );
  
        const request: BbsCreateProofRequest = {
          signature,
          publicKey,
          messages,
          nonce: "0123456789",
          revealed: [0],
        };
  
        const proof = createProof(request);
        expect(proof.length).toEqual(693);
      });
  
      it("should create proof revealing all messages from multi-message signature", () => {
        const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
        const publicKey = base64Decode(
          "DG1pb04J5kNTjAk6C+9Sx7i9fMivdkkhE26hPpSbOAcfUxaf62R1pw3AXU1x1VktCiZ79AWeF4RzSJiON+2eLnhysvCh+qQ+k1OlA0y6Qv7p7h/7+puSwejqDs4brfJIBJ5rKfoyIdX3q1m5nAvLBzzw5L+mIQZjULIgL2O+rPrj3cWKboM2231UMXGLd1lrDgpqeHCqlImoNe2laq+LjjAanGC+oZEmT8itw5QipZE+UkydUlvw0/1v/unn6krk"
        );
        const signature = base64Decode(
          "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
        );
  
        const request: BbsCreateProofRequest = {
          signature,
          publicKey,
          messages,
          nonce: base64Encode(randomBytes(10)),
          revealed: [0, 1, 2],
        };
  
        const proof = createProof(request);
        expect(proof.length).toEqual(693); //TODO add a reason for this and some constants?
      });
  
      it("should create proof revealing single messages from multi-message signature", () => {
        const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
        const publicKey = base64Decode(
          "DG1pb04J5kNTjAk6C+9Sx7i9fMivdkkhE26hPpSbOAcfUxaf62R1pw3AXU1x1VktCiZ79AWeF4RzSJiON+2eLnhysvCh+qQ+k1OlA0y6Qv7p7h/7+puSwejqDs4brfJIBJ5rKfoyIdX3q1m5nAvLBzzw5L+mIQZjULIgL2O+rPrj3cWKboM2231UMXGLd1lrDgpqeHCqlImoNe2laq+LjjAanGC+oZEmT8itw5QipZE+UkydUlvw0/1v/unn6krk"
        );
        const signature = base64Decode(
          "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
        );
  
        const request: BbsCreateProofRequest = {
          signature,
          publicKey,
          messages,
          nonce: base64Encode(randomBytes(10)),
          revealed: [0],
        };
  
        const proof = createProof(request);
        expect(proof.length).toEqual(789); //TODO why?????? add a reason for this and some constants?
      });
  
      it("should create proof revealing multiple messages from multi-message signature", () => {
        const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
        const publicKey = base64Decode(
          "DG1pb04J5kNTjAk6C+9Sx7i9fMivdkkhE26hPpSbOAcfUxaf62R1pw3AXU1x1VktCiZ79AWeF4RzSJiON+2eLnhysvCh+qQ+k1OlA0y6Qv7p7h/7+puSwejqDs4brfJIBJ5rKfoyIdX3q1m5nAvLBzzw5L+mIQZjULIgL2O+rPrj3cWKboM2231UMXGLd1lrDgpqeHCqlImoNe2laq+LjjAanGC+oZEmT8itw5QipZE+UkydUlvw0/1v/unn6krk"
        );
        const signature = base64Decode(
          "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
        );
  
        const request: BbsCreateProofRequest = {
          signature,
          publicKey,
          messages,
          nonce: base64Encode(randomBytes(10)),
          revealed: [0, 2],
        };
  
        const proof = createProof(request);
        expect(proof.length).toEqual(741); //TODO evaluate this length properly add a reason for this and some constants?
      });
    });
});