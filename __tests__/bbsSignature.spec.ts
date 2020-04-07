import { generateKeyPair, BbsSignRequest, sign, verify } from "../src";

describe("bbsSignature", () => {
  const domainSeperationTag = "BBSSignature2020";

  describe("sign", () => {
    const blsKeyPair = generateKeyPair();
    const messages = [ "ExampleMessage" ];

    it("should be able to sign", () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        domainSeperationTag,
        messages
      }
      const signature = sign(request);
      console.log(signature);
    });
  });
  describe("verify", () => {
    it("should be able to verify valid signature", () => {

    });
  });
});
