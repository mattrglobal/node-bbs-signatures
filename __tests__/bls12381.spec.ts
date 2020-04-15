import { randomBytes } from "@stablelib/random";
import { generateKeyPair, DEFAULT_PUBLIC_KEY_LENGTH, DEFAULT_PRIVATE_KEY_LENGTH } from "../src";

describe("bls12381", () => {
  it("should be able to generate a key pair", () => {
    const result = generateKeyPair();
    expect(result).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey.length).toEqual(DEFAULT_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH);
  });

  it("should be able to generate a key pair with a seed", () => {
    const seed = randomBytes(50);
    const result = generateKeyPair(seed);
    expect(result.publicKey).toBeDefined();
    expect(result.secretKey).toBeDefined();
    expect(result.secretKey.length).toEqual(DEFAULT_PRIVATE_KEY_LENGTH);
    expect(result.publicKey.length).toEqual(DEFAULT_PUBLIC_KEY_LENGTH);
  });
});
