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
  BbsSignRequest,
  BbsVerifyProofRequest,
  BbsBlindSignRequest,
  BbsCreateProofRequest,
  sign,
  verify,
  BbsVerifyRequest,
  DEFAULT_PUBLIC_KEY_LENGTH,
} from "../src";
import { Coder } from "@stablelib/base64";
import { randomBytes } from "crypto";
import { blindSign, createProof, verifyProof } from "../src/bbsSignature";

const base64Encode = (bytes: Uint8Array): string => {
  const coder = new Coder();
  return coder.encode(bytes);
};

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  const domainSeparationTag = "BBSSignature2020";

  describe("sign", () => {
    const blsKeyPair = generateBls12381KeyPair();

    it("should sign a single message", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage"],
      };
      const signature = sign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should sign multiple messages", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"],
      };
      const signature = sign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag: "",
        messages: ["ExampleMessage"],
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when messages empty", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: [],
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when secret key invalid length", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.publicKey,
        domainSeparationTag,
        messages: ["ExampleMessage"],
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });
  });

  describe("blindSign", () => {
    const blsKeyPair = generateBls12381KeyPair();

    it("should sign with a single known message", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should sign with a multiple known messages", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"],
        messageCount: 4,
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag: "",
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when secret key invalid length", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: randomBytes(10),
        domainSeparationTag,
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      expect(() => blindSign(request)).toThrowError("Failed to sign");
    });
  });

  describe("blindSign", () => {
    const blsKeyPair = generateBls12381KeyPair();

    it("should sign a single known message", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should sign multiple known messages", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"],
        messageCount: 4,
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH + 1); //TODO why is the signature one more than the public key?
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeparationTag: "",
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when secret key invalid length", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: randomBytes(10),
        domainSeparationTag,
        messages: ["ExampleMessage"],
        messageCount: 2,
      };
      expect(() => blindSign(request)).toThrowError("Failed to sign");
    });
  });

  describe("verify", () => {
    it("should verify valid signature with a single message", () => {
      const messages = ["ExampleMessage"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const signature = base64Decode(
        "BAN3Hm/9F8dmVJE7yYJkQz6XIH1Am454LBXjU5kEcRrX4xYZ7f9+ztqkSRr5BD56IBPRXngoo2u14UqJwSr/lgbF7bw1AIdUX+Ipnez9Y/eh466QaymKBCdFdkjXBKakRQAAAAAAAAAAAAAAAAAAAABxjP0o2lcC86xG3shFMloCBh4Bn3jh4UW3foRkalSglgAAAAAAAAAAAAAAAAAAAABnJvxeDnd0vNLpOw8z6Gu1cpvQG01ptYeORAIHYmJ/ug=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeparationTag,
        messages,
        signature,
      };
      expect(verify(verifyRequest)).toBeTruthy();
    });

    it("should verify valid signature with multiple messages", () => {
      const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
      const publicKey = base64Decode(
        "C+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxckBBUEOLsDbilWBVuGqEt57Glhir8lnZ/Ie3AUQK7tmEEpz/CyxqauEK6YArR4mihEFwuEd0An1yD3M8s5yUHzYsKjgXPgABZgvIm6h/ta0Nif1kdmf8I9ba619SPnTJ6t"
      );
      const signature = base64Decode(
        "BBONgUs1Jrw1NP0IJAfvs5bDj9g2v67Q39Gj4twPmAM0o2cqZ4xZJj3Mf4TTEvYVoBjtuVMYtjdeF8CuD26exdKMuXtngw6lF0NY6qpSN7SnhqGqpx1DVwVKixxeg3Lo9AAAAAAAAAAAAAAAAAAAAAAVLr+7I/vt6h/zDpLngprGHemtf2rLBWtZsJntPXE//AAAAAAAAAAAAAAAAAAAAABCCvCKuwjn80ALQRtrIR8Sv7GCpR/zlAHyaqb5TCFuyw=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeparationTag,
        messages,
        signature,
      };
      expect(verify(verifyRequest)).toBeTruthy();
    });
    it("should not verify valid signature with wrong single message", () => {
      const messages = ["BadMessage"];
      const publicKey = base64Decode(
        "FhgS20glFXybq5/tnvJwMot1kt3wfYBzEUdoLYV/n+/4ruTeSDdDzSKGJVwMt4atBin5dEfDo3AfrXtJb1qDAmfjlQ08DIT+46bWi4EKls5aotCu8aqVihpBX1AX63aDE4rRAleyMz1z2UF1iH0Kqkrkakql63bURKPuOYY6apH6rhyZPZD5i347bCfmsQkbCqbfkf+VOAebbdadstlFh+rRfyHSJDGZoJlgwdgekuNEzUDLObSlHujmH1g8NRsN"
      );
      const signature = base64Decode(
        "BBACjR3gBNCPdarBCNScVvLeH+5YZnVmU30D0Kp7J1fAtUn0SqcKYxfOjnNc8HlWIxSEOC3IfmParRnRWla1xeiJ/oje3thMb+yb1ZlhsH5w58Qy9K52jJeximsvpLAStwAAAAAAAAAAAAAAAAAAAAAzE3sZuhpY8ti14pkVh2QmwF77nwNO7iYwG/QGT47lpQAAAAAAAAAAAAAAAAAAAAA7J9IaPfRcApuZoHSI2xCteZpkruUrswMaymm6qd67qw=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeparationTag,
        messages,
        signature,
      };
      expect(verify(verifyRequest)).toBeFalsy();
    });
    it("should not verify valid signature with wrong messages", () => {
      const messages = ["BadMessage", "BadMessage", "BadMessage"];
      const publicKey = base64Decode(
        "DG1pb04J5kNTjAk6C+9Sx7i9fMivdkkhE26hPpSbOAcfUxaf62R1pw3AXU1x1VktCiZ79AWeF4RzSJiON+2eLnhysvCh+qQ+k1OlA0y6Qv7p7h/7+puSwejqDs4brfJIBJ5rKfoyIdX3q1m5nAvLBzzw5L+mIQZjULIgL2O+rPrj3cWKboM2231UMXGLd1lrDgpqeHCqlImoNe2laq+LjjAanGC+oZEmT8itw5QipZE+UkydUlvw0/1v/unn6krk"
      );
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeparationTag,
        messages,
        signature,
      };
      expect(verify(verifyRequest)).toBeFalsy();
    });
    it("should throw error when domain seperation tag empty", () => {
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );
      const blsKeyPair = generateBls12381KeyPair();
      const request: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        domainSeparationTag: "",
        messages: ["ExampleMessage"],
        signature,
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });
    it("should throw error when messages empty", () => {
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );
      const blsKeyPair = generateBls12381KeyPair();
      const request: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        domainSeparationTag,
        messages: [],
        signature,
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });
    it("should throw error when public key invalid length", () => {
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );
      const request: BbsVerifyRequest = {
        publicKey: new Uint8Array(20),
        domainSeparationTag,
        messages: [],
        signature,
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });
  });

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
        domainSeparationTag,
        revealed: [0],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(693); //TODO add a reason for this and some constants?
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
        nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
        domainSeparationTag,
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
        nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
        domainSeparationTag,
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
        nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
        domainSeparationTag,
        revealed: [0, 2],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(741); //TODO evaluate this length properly add a reason for this and some constants?
    });
  });

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
        domainSeparationTag,
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
        domainSeparationTag,
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
        domainSeparationTag,
        revealed: [0, 1, 2],
      };
      const proof = createProof(request);

      const response: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 3,
        messages,
        nonce: "0123456789",
        domainSeparationTag,
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
        domainSeparationTag,
        revealed: [],
      };
      const proof = createProof(request);

      const response: BbsVerifyProofRequest = {
        proof,
        publicKey,
        messageCount: 3,
        messages: [],
        nonce: "0123456789",
        domainSeparationTag,
        revealed: [],
      };
      expect(verifyProof(response)).toBeTruthy();
    });
  });
});
