// import { generateKeyPair, BbsSignRequest, sign, verify } from "../src";

// describe("bbsSignature", () => {
//   const blsKeyPair = generateKeyPair(); //TODO use a seed
//   const exampleMessages; //TODO get the messages to sign
//   const domainSeperationTag = "DomainSeperation"; //TODO string to bytes

//   it("should be able to sign", () => {
//     const request: BbsSignRequest = {
//       privateKey: blsKeyPair.secretKey,
//       domainSeperationTag,
//       exampleMessages
//     }
//     const signature = sign(request);
//     expect(signature).toBeDefined();
//     expect(signature.length).toEqual(48);
//   });
// });
