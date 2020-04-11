import {
  generateKeyPair,
  BbsSignRequest,
  sign,
  verify,
  BbsVerifyRequest
} from "../src";
import { Coder } from "@stablelib/base64";

const base64Encode = (bytes: Uint8Array): string => {
  const coder = new Coder();
  return coder.encode(bytes);
};

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  const domainSeperationTag = "BBSSignature2020";

  describe("sign", () => {
    const blsKeyPair = generateKeyPair();

    it("should be able to sign with a single message", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage"]
      };
      const signature = sign(request);
      expect(signature.length).toEqual(193);
    });

    it("should be able to sign with multiple messages", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"]
      };
      const signature = sign(request);
      expect(signature.length).toEqual(193);
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag: "",
        messages: ["ExampleMessage"]
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it.todo("should throw error when messages empty");

    // TODO ^ test currently failing
    // () => {
    //   const request: BbsSignRequest = {
    //     secretKey: blsKeyPair.secretKey,
    //     domainSeperationTag,
    //     messages: []
    //   };
    //   expect(() => sign(request)).toThrowError("Failed to sign");
    // }

    it("should throw error when secret key invalid length", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.publicKey,
        domainSeperationTag,
        messages: ["ExampleMessage"]
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });
  });

  describe("verify", () => {
    it("should be able to verify valid signature with a single message", () => {
      const messages = ["ExampleMessage"];
      const publicKey = base64Decode(
        "FhgS20glFXybq5/tnvJwMot1kt3wfYBzEUdoLYV/n+/4ruTeSDdDzSKGJVwMt4atBin5dEfDo3AfrXtJb1qDAmfjlQ08DIT+46bWi4EKls5aotCu8aqVihpBX1AX63aDE4rRAleyMz1z2UF1iH0Kqkrkakql63bURKPuOYY6apH6rhyZPZD5i347bCfmsQkbCqbfkf+VOAebbdadstlFh+rRfyHSJDGZoJlgwdgekuNEzUDLObSlHujmH1g8NRsN"
      );
      const signature = base64Decode(
        "BBACjR3gBNCPdarBCNScVvLeH+5YZnVmU30D0Kp7J1fAtUn0SqcKYxfOjnNc8HlWIxSEOC3IfmParRnRWla1xeiJ/oje3thMb+yb1ZlhsH5w58Qy9K52jJeximsvpLAStwAAAAAAAAAAAAAAAAAAAAAzE3sZuhpY8ti14pkVh2QmwF77nwNO7iYwG/QGT47lpQAAAAAAAAAAAAAAAAAAAAA7J9IaPfRcApuZoHSI2xCteZpkruUrswMaymm6qd67qw=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeperationTag,
        messages,
        signature
      };
      expect(verify(verifyRequest)).toBeTruthy();
    });

    it("should be able to verify valid signature with multiple messages", () => {
      const messages = ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"];
      const publicKey = base64Decode(
        "DG1pb04J5kNTjAk6C+9Sx7i9fMivdkkhE26hPpSbOAcfUxaf62R1pw3AXU1x1VktCiZ79AWeF4RzSJiON+2eLnhysvCh+qQ+k1OlA0y6Qv7p7h/7+puSwejqDs4brfJIBJ5rKfoyIdX3q1m5nAvLBzzw5L+mIQZjULIgL2O+rPrj3cWKboM2231UMXGLd1lrDgpqeHCqlImoNe2laq+LjjAanGC+oZEmT8itw5QipZE+UkydUlvw0/1v/unn6krk"
      );
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );

      const verifyRequest: BbsVerifyRequest = {
        publicKey,
        domainSeperationTag,
        messages,
        signature
      };
      expect(verify(verifyRequest)).toBeTruthy();
    });

    it("should throw error when domain seperation tag empty", () => {
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );
      const blsKeyPair = generateKeyPair();
      const request: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        domainSeperationTag: "",
        messages: ["ExampleMessage"],
        signature
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });

    it.todo("should throw error when messages empty");

    // TODO ^ test currently failing
    // () => {
    //   const signature = base64Decode(
    //     "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
    //   );
    //   const blsKeyPair = generateKeyPair();
    //   const request: BbsVerifyRequest = {
    //     publicKey: blsKeyPair.publicKey,
    //     domainSeperationTag,
    //     messages: [],
    //     signature
    //   };
    //   expect(() => verify(request)).toThrowError("Failed to verify");
    // }

    it("should throw error when public key invalid length", () => {
      const signature = base64Decode(
        "BBkDTwJ6H3LLVd9wf/p5X4ZzNnFJ7usnbzxmcjcSxF2t+VWcqq6a8JYAYLeAwB0tMwi/Tu1cROZ2ioBDh0+HoV2Aj8UIYxLa5fZn1E0hLzeQadURmI7nqtofopMnXeRG8gAAAAAAAAAAAAAAAAAAAAAAxXagffQjZCCLLPu9m/8/OEl/nSNsArq30nY2hgqmYAAAAAAAAAAAAAAAAAAAAABEhciXgV9wG+MOrEb4vkFPdDGae+wIIzRJhJjKK2B7ng=="
      );
      const blsKeyPair = generateKeyPair();
      const request: BbsVerifyRequest = {
        publicKey: new Uint8Array(20),
        domainSeperationTag,
        messages: [],
        signature
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });
  });
});
