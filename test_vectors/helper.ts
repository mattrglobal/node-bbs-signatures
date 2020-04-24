import { generateBls12381KeyPair, blsSign, bls12381toBbs } from "../src";
import { Coder } from "@stablelib/base64";
import { randomBytes } from "@stablelib/random";
import { createProof } from "../src/bbsSignature";

const base64Encode = (bytes: Uint8Array): string => {
    const coder = new Coder();
    return coder.encode(bytes);
};

const generateRandomMessages = (numberOfMessages: number, messageSizeInBytes: number): string[] => {
    const messages: string[] = [];
    for (let i = 0; i < numberOfMessages; i++) {
      messages[i] = base64Encode(randomBytes(messageSizeInBytes));
    }
    return messages;
};

export const generateTestVector = (vectorName: string, numberOfMessages: number, messageSizeInBytes: number, numberRevealedInProof: number): any => {
    const nonce = base64Encode(randomBytes(20));
    const blsKeyPair = generateBls12381KeyPair();
    const bbsKeyPair = bls12381toBbs({ keyPair: blsKeyPair, messageCount: numberOfMessages });

    const signRequest = {
        keyPair: blsKeyPair,
        messages: generateRandomMessages(numberOfMessages, messageSizeInBytes),
    };

    const signature = blsSign(signRequest);

    const proofRequest = {
        signature,
        publicKey: bbsKeyPair.publicKey,
        messages: signRequest.messages,
        revealed: [...Array(numberRevealedInProof).keys()],
        nonce,
    };

    const proof = createProof(proofRequest);

    return {
        vectorName,
        blsKeyPair: {
            privateKey: base64Encode(blsKeyPair.secretKey as Uint8Array),
            publicKey: base64Encode(blsKeyPair.publicKey as Uint8Array),
        },
        bbsPublicKey: base64Encode(bbsKeyPair.publicKey as Uint8Array),
        messageCount: bbsKeyPair.messageCount,
        messages: signRequest.messages,
        signature: base64Encode(signature),
        proof: {
            proof: base64Encode(proof),
            revealed: proofRequest.revealed,
            nonce
        }
    };
}