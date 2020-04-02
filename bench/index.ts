import { benchmark, report } from "@stablelib/benchmark";
import { generateKeyPair } from "../src/bls12381";

report(
  "BLS 12-381 Key Generation",
  benchmark(() => generateKeyPair())
);
