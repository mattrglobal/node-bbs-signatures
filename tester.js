const { sign } = require("./lib/bbsSignature");
const { generateKeyPair } = require("./lib/bls12381");

const domainSeperationTag = "BBSSignature2020";
const blsKeyPair = generateKeyPair();
const messages = [ "ExampleMessage" ];

const request = {
    secretKey: blsKeyPair.secretKey,
    domainSeperationTag,
    messages
  }
  
const signature = sign(request);
console.log(signature);
