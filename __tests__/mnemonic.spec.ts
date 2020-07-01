import { generateBls12381KeyPair } from "../src";
import crypto from "crypto";
import * as mnemonic from "../src/mnemonic/mnemonic";

describe("mnemonic", () => {
  it("should return 25 words mnemonic from secret key seed", () => {
    const keyPair = generateBls12381KeyPair();
    const mn = mnemonic.mnemonicFromSeed(keyPair.secretKey as Uint8Array);
    expect(mn.split(" ").length).toStrictEqual(25);
  });

  it("should be able to converted back to key", () => {
    const keyPair = generateBls12381KeyPair();
    const mn = mnemonic.mnemonicFromSeed(keyPair.secretKey as Uint8Array);
    const targetKey = mnemonic.seedFromMnemonic(mn);
    expect(targetKey).toStrictEqual(keyPair.secretKey as Uint8Array);
  });

  it("should pass zero vector test", () => {
    const seed = new Uint8Array([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
    ]);
    const mn =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const targetKey = mnemonic.mnemonicFromSeed(seed);
    expect(targetKey).toStrictEqual(mn);
  });

  it("should fail to verify mnemonic with invalid checksum word", () => {
    const seed = crypto.randomBytes(32);
    const mn = mnemonic.mnemonicFromSeed(seed);
    // Shuffle bits
    const shuffledMn = mn.slice(0, mn.length - 1) + "h";

    // https://jestjs.io/docs/en/expect.html#tothrowerror
    function seedFromInvalidChecksumMnemonic(): void {
      mnemonic.seedFromMnemonic(shuffledMn);
    }

    expect(seedFromInvalidChecksumMnemonic).toThrowError(mnemonic.ERROR_FAILED_TO_DECODE_MNEMONIC);
  });

  it("should fail to verify invalid mnemonic", () => {
    const mn =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon venue abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

    function seedFromInvalidMnemonic(): void {
      mnemonic.seedFromMnemonic(mn);
    }

    expect(seedFromInvalidMnemonic).toThrowError(mnemonic.ERROR_FAILED_TO_DECODE_MNEMONIC);
  });

  it("should fail to verify mnemonic with invalid word", () => {
    const mn =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon venues abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

    function seedFromInvalidMnemonic(): void {
      mnemonic.seedFromMnemonic(mn);
    }

    expect(seedFromInvalidMnemonic).toThrowError(mnemonic.ERROR_WORD_NOT_IN_WORDSLIST);
  });
});
