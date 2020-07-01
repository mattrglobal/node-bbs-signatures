import english from "./wordlists/english";
import crypto from "crypto";

const ERROR_FAILED_TO_DECODE_MNEMONIC = Error("Failed to decode mnemonic");
const ERROR_WORD_NOT_IN_WORDSLIST = Error("Mnemonic contains a word not in the wordslist");

const SEED_BYTES_LENGTH = 32;

function mnemonicFromSeed(seed: Uint8Array): string {
  if (seed.length !== SEED_BYTES_LENGTH) {
    throw new RangeError(`Seed length must be ${SEED_BYTES_LENGTH}`);
  }

  const uint11Array = UInt8ArrayToUInt11Array(seed);
  const words = applyWords(uint11Array);
  const checksumWord = computeChecksum(seed);

  return words.join(" ") + " " + checksumWord;
}

function seedFromMnemonic(mnemonic: string): Uint8Array {
  const words = mnemonic.split(" ");
  const key = words.slice(0, 24);

  // Check all words are present in the wordslist
  for (let word of key) {
    if (english.indexOf(word) === -1) throw ERROR_WORD_NOT_IN_WORDSLIST;
  }

  const checksumWord = words[words.length - 1];
  const uint11Array = key.map((word) => english.indexOf(word));

  let uint8Array = UInt11ArrayToUInt8Array(uint11Array);

  // https://github.com/algorand/js-algorand-sdk/blob/develop/src/mnemonic/mnemonic.js#L32
  // We need to chop the last byte -
  // the short explanation - Since 256 is not divisible by 11, we have an extra 0x0 byte.
  // The longer explanation - When splitting the 256 bits to chunks of 11, we get 23 words and a left over of 3 bits.
  // This left gets padded with another 8 bits to the create the 24th word.
  // While converting back to byte array, our new 264 bits array is divisible by 8 but the last byte is just the padding.

  // check that we have 33 bytes long array as expected
  if (uint8Array.length !== 33) throw ERROR_FAILED_TO_DECODE_MNEMONIC;

  // check that the last byte is actually 0x0
  if (uint8Array[uint8Array.length - 1] !== 0x0) throw ERROR_FAILED_TO_DECODE_MNEMONIC;

  // chop
  uint8Array = uint8Array.slice(0, uint8Array.length - 1);

  const computedChecksumWord = computeChecksum(uint8Array);

  if (checksumWord === computedChecksumWord) return uint8Array;

  throw ERROR_FAILED_TO_DECODE_MNEMONIC;
}

/* Helpers */

// https://stackoverflow.com/a/51452614
function UInt8ArrayToUInt11Array(uint8: Uint8Array): number[] {
  let uint11: any[] = [];
  let acc = 0;
  let accBits = 0;

  function add(octet: number) {
    acc = (octet << accBits) | acc;
    accBits += 8;
    if (accBits >= 11) {
      uint11.push(acc & 0x7ff);
      acc >>= 11;
      accBits -= 11;
    }
  }

  function flush() {
    if (accBits) {
      uint11.push(acc);
    }
  }

  uint8.forEach(add);
  flush();
  return uint11;
}

// https://stackoverflow.com/a/51452614
function UInt11ArrayToUInt8Array(uint11: number[]): Uint8Array {
  let uint8: any[] = [];
  let acc = 0;
  let accBits = 0;

  function add(ui11: number) {
    acc = (ui11 << accBits) | acc;
    accBits += 11;
    while (accBits >= 8) {
      uint8.push(acc & 0xff);
      acc >>= 8;
      accBits -= 8;
    }
  }

  function flush() {
    if (accBits) {
      uint8.push(acc);
    }
  }

  uint11.forEach(add);
  flush();
  return new Uint8Array(uint8);
}

function applyWords(nums: number[]) {
  return nums.map((n) => english[n]);
}

function computeChecksum(seed: Uint8Array): any {
  const hashBuffer = crypto.createHash("sha256").update(seed).digest();
  const uint8HashBuffer = new Uint8Array(hashBuffer);
  const uint11HashBuffer = UInt8ArrayToUInt11Array(uint8HashBuffer);
  const words = applyWords(uint11HashBuffer);

  return words[0];
}

export default { mnemonicFromSeed, seedFromMnemonic, ERROR_FAILED_TO_DECODE_MNEMONIC, ERROR_WORD_NOT_IN_WORDSLIST };
