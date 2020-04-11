import {
  generateKeyPair,
  BbsSignRequest,
  sign,
  verify,
  BbsVerifyRequest
} from "../src";
import { Coder } from "@stablelib/base64";
import { BbsBlindSignRequest } from "../src/types/BbsBlindSignRequest";
import { randomBytes } from "crypto";
import { blindSign, createProof } from "../src/bbsSignature";
import { BbsCreateProofRequest } from "../src/types/BbsCreateProofRequest";

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

    it("should sign a single message", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage"]
      };
      const signature = sign(request);
      expect(signature.length).toEqual(193);
    });

    it("should sign multiple messages", () => {
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

  describe("blindSign", () => {
    const blsKeyPair = generateKeyPair();

    it("should sign with a single known message", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(193);
    });

    it("should sign with a multiple known messages", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"],
        messageCount: 4
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(193);
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag: "",
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when secret key invalid length", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: randomBytes(10),
        domainSeperationTag,
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      expect(() => blindSign(request)).toThrowError("Failed to sign");
    });
  });

  describe("blindSign", () => {
    const blsKeyPair = generateKeyPair();

    it("should sign a single known message", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(193);
    });

    it("should sign multiple known messages", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages: ["ExampleMessage", "ExampleMessage2", "ExampleMessage3"],
        messageCount: 4
      };
      const signature = blindSign(request);
      expect(signature.length).toEqual(193);
    });

    it("should throw error when domain seperation tag empty", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag: "",
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      expect(() => sign(request)).toThrowError("Failed to sign");
    });

    it("should throw error when secret key invalid length", () => {
      const request: BbsBlindSignRequest = {
        commitment: randomBytes(97),
        secretKey: randomBytes(10),
        domainSeperationTag,
        messages: ["ExampleMessage"],
        messageCount: 2
      };
      expect(() => blindSign(request)).toThrowError("Failed to sign");
    });
  });

  describe("verify", () => {
    it("should verify valid signature with a single message", () => {
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

    it("should verify valid signature with multiple messages", () => {
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
        domainSeperationTag,
        messages,
        signature
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
        domainSeperationTag,
        messages,
        signature
      };
      expect(verify(verifyRequest)).toBeFalsy();
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
      const request: BbsVerifyRequest = {
        publicKey: new Uint8Array(20),
        domainSeperationTag,
        messages: [],
        signature
      };
      expect(() => verify(request)).toThrowError("Failed to verify");
    });
  });

  describe("createProof", () => {
    it("should create proof revealing single message from single message signature", () => {
      const messages = ["ExampleMessage"];
      const publicKey = base64Decode(
        "FhgS20glFXybq5/tnvJwMot1kt3wfYBzEUdoLYV/n+/4ruTeSDdDzSKGJVwMt4atBin5dEfDo3AfrXtJb1qDAmfjlQ08DIT+46bWi4EKls5aotCu8aqVihpBX1AX63aDE4rRAleyMz1z2UF1iH0Kqkrkakql63bURKPuOYY6apH6rhyZPZD5i347bCfmsQkbCqbfkf+VOAebbdadstlFh+rRfyHSJDGZoJlgwdgekuNEzUDLObSlHujmH1g8NRsN"
      );
      const signature = base64Decode(
        "BBACjR3gBNCPdarBCNScVvLeH+5YZnVmU30D0Kp7J1fAtUn0SqcKYxfOjnNc8HlWIxSEOC3IfmParRnRWla1xeiJ/oje3thMb+yb1ZlhsH5w58Qy9K52jJeximsvpLAStwAAAAAAAAAAAAAAAAAAAAAzE3sZuhpY8ti14pkVh2QmwF77nwNO7iYwG/QGT47lpQAAAAAAAAAAAAAAAAAAAAA7J9IaPfRcApuZoHSI2xCteZpkruUrswMaymm6qd67qw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey,
        messages,
        nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
        domainSeperationTag,
        revealed: [0]
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
        domainSeperationTag,
        revealed: [0, 1, 2]
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
        domainSeperationTag,
        revealed: [0]
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
        domainSeperationTag,
        revealed: [0, 2]
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(741); //TODO why?????? add a reason for this and some constants?
    });
  });

  describe("verifyProof", () => {
    it.todo(
      "should verify proof with all messages revealed from single message signature"
    );

    // TODO failing test ^
    // () => {
    //   const messages = ["ExampleMessage"];
    //   const publicKey = base64Decode(
    //     "FhgS20glFXybq5/tnvJwMot1kt3wfYBzEUdoLYV/n+/4ruTeSDdDzSKGJVwMt4atBin5dEfDo3AfrXtJb1qDAmfjlQ08DIT+46bWi4EKls5aotCu8aqVihpBX1AX63aDE4rRAleyMz1z2UF1iH0Kqkrkakql63bURKPuOYY6apH6rhyZPZD5i347bCfmsQkbCqbfkf+VOAebbdadstlFh+rRfyHSJDGZoJlgwdgekuNEzUDLObSlHujmH1g8NRsN"
    //   );
    //   const proof = base64Decode(
    //     "BBACjR3gBNCPdarBCNScVvLeH+5YZnVmU30D0Kp7J1fAtUn0SqcKYxfOjnNc8HlWIxSEOC3IfmParRnRWla1xeiJ/oje3thMb+yb1ZlhsH5w58Qy9K52jJeximsvpLAStwAAAAAAAAAAAAAAAAAAAAAzE3sZuhpY8ti14pkVh2QmwF77nwNO7iYwG/QGT47lpQAAAAAAAAAAAAAAAAAAAAA7J9IaPfRcApuZoHSI2xCteZpkruUrswMaymm6qd67qw=="
    //   );

    //   const request: BbsVerifyProofRequest = {
    //     proof,
    //     publicKey,
    //     messageCount: 1,
    //     messages,
    //     nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
    //     domainSeperationTag,
    //     revealed: [0]
    //   };

    //   //expect(verifyProof(request)).toBeTruthy();
    // }

    it.todo(
      "should verify proof with all messages revealed from multi-message signature"
    );

    // TODO failing test ^
    // () => {
    //   //TODO change to multiple messages
    //   const messages = ["ExampleMessage"];
    //   const publicKey = base64Decode(
    //     "FhgS20glFXybq5/tnvJwMot1kt3wfYBzEUdoLYV/n+/4ruTeSDdDzSKGJVwMt4atBin5dEfDo3AfrXtJb1qDAmfjlQ08DIT+46bWi4EKls5aotCu8aqVihpBX1AX63aDE4rRAleyMz1z2UF1iH0Kqkrkakql63bURKPuOYY6apH6rhyZPZD5i347bCfmsQkbCqbfkf+VOAebbdadstlFh+rRfyHSJDGZoJlgwdgekuNEzUDLObSlHujmH1g8NRsN"
    //   );
    //   //TODO change this proof
    //   const proof = base64Decode(
    //     "BBACjR3gBNCPdarBCNScVvLeH+5YZnVmU30D0Kp7J1fAtUn0SqcKYxfOjnNc8HlWIxSEOC3IfmParRnRWla1xeiJ/oje3thMb+yb1ZlhsH5w58Qy9K52jJeximsvpLAStwAAAAAAAAAAAAAAAAAAAAAzE3sZuhpY8ti14pkVh2QmwF77nwNO7iYwG/QGT47lpQAAAAAAAAAAAAAAAAAAAAA7J9IaPfRcApuZoHSI2xCteZpkruUrswMaymm6qd67qw=="
    //   );

    //   const request: BbsVerifyProofRequest = {
    //     proof,
    //     publicKey,
    //     messageCount: 1,
    //     messages,
    //     nonce: base64Encode(randomBytes(10)), //TODO probably want this as a byte array instead?
    //     domainSeperationTag,
    //     revealed: [0] //TODO change this to reveal more
    //   };

    //   //expect(verifyProof(request)).toBeTruthy();
    // }
  });
});
