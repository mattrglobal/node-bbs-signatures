import { benchmark, report } from "@stablelib/benchmark";
import { generateKeyPair } from "../src/bls12381";
import { sign, verify } from "../src/bbsSignature";
import { Coder } from "@stablelib/base64";

const base64Encode = (bytes: Uint8Array): string => {
  const coder = new Coder();
  return coder.encode(bytes);
}

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
}

const domainSeperationTag = "BBSSignature2020";
const blsKeyPair = {
  secretKey: base64Decode("AAAAAAAAAAAAAAAAAAAAAFutvcqd+rMKit2/lHuUBrarW0MQHYXEhdwRiDAWF6xU"),
  publicKey: base64Decode("BTOwo3q9pwqyCJA7H14HCg21e/gB079teu1asBO15o4q25t2cRFEwjDdTxly9na3Fqio+vkgftdPROoQR5PRBvkbOksEEuqROwdDw9d32LqUx2yEEhKnBialXfkv/XPACJNdDzy8dPFCXq2kQI1FdsNRWpSFGdbMXIwwNgu6lLRtkJLd7U2ODwqjlC76XaGUA+svFUnaG46CpOidVMkZeVlhwwG4NlCdeVrX4oczdY5nuXHzx0Utxc3KmNgiJoKT")
};

const oneMessageSignRequestRequest = {
    secretKey: blsKeyPair.secretKey,
    domainSeperationTag,
    messages: [ "ExampleMessage" ]
}

const tenMessageSignRequest = {
    secretKey: blsKeyPair.secretKey,
    domainSeperationTag,
    messages: [ "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage", 
                "ExampleMessage" ]
}

const oneMessageVerifyRequest = {
  publicKey: blsKeyPair.publicKey,
  signature: base64Decode("BBSCxYOjrbhPc2+M/9qHdA6EzbD3U8DznJxJs7SYg1hPv2lNjB6Fc7Fv0dPgQHjLHhYrGApKZEdsuL3zPMzhjGbiyrh9Rsa2jsSn8nCui4v2QnKSUXCXG++DnhQbCMvjRwAAAAAAAAAAAAAAAAAAAABkTRu/B1QJvROL4hrpMpNsPNBjN9v/+FAG1KIFHoIjTwAAAAAAAAAAAAAAAAAAAABaVuLs/ZFEmKjXtgSf3euJ3p0TuekCEtW3kYkm2VdV7Q=="),
  domainSeperationTag,
  messages: [ "ExampleMessage" ]
}

const tenMessageVerifyRequest = {
  publicKey: blsKeyPair.publicKey,
  signature: base64Decode("BAZiCPZ6iHmDXkimWhFa+9p2TTJ2GZ1MHik7T41Q1MFvZS9sNX4nFUlRQn9VxpRUCw7is9he1jek/FwBfxqGk5CNLGeTNiXC1H2ymsg1GUiNFaS6kXwunOfH1jx2lEcCMQAAAAAAAAAAAAAAAAAAAAA3wfmN2jzk8GNTvcPaE/teCAM5BsILmZbpLN3GSGI8CwAAAAAAAAAAAAAAAAAAAAAwML+DrJ+rtCg2SgKjfSzMNjyew+h9Uz9hjA8a36DwWQ=="),
  domainSeperationTag,
  messages: [ "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage", 
            "ExampleMessage" ]
}

report(
  "BLS 12-381 Key Generation",
  benchmark(() => generateKeyPair())
);

report(
  "BBS Sign 1 message",
  benchmark(() => sign(oneMessageSignRequestRequest))
);

report(
  "BBS Sign 10 message",
  benchmark(() => sign(tenMessageSignRequest))
);

report(
  "BBS Verify 1 message",
  benchmark(() => verify(oneMessageVerifyRequest))
);

report(
  "BBS Verify 10 message",
  benchmark(() => verify(tenMessageVerifyRequest))
);