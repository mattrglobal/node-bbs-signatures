import { BbsSignRequest } from "../src";
import { randomBytes } from "crypto";
import { Coder } from "@stablelib/base64";

export const generateMessages = (numberOfMessages: number, messageSizeInBytes: number): string[] => {
  const coder = new Coder();
  const messages: string[] = [];
  for (let i = 0; i < numberOfMessages; i++) {
    messages[i] = coder.encode(randomBytes(messageSizeInBytes));
  }
  return messages;
};

export const generateSignRequest = (
  secretKey: Uint8Array,
  domainSeparationTag: string,
  numberOfMessages: number,
  messageSizeInBytes: number
): BbsSignRequest => {
  return {
    secretKey,
    domainSeparationTag,
    messages: generateMessages(numberOfMessages, messageSizeInBytes),
  };
};
