/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BbsCreateProofRequest, createProof, blsCreateProof } from "../../src";
import { Coder } from "@stablelib/base64";
import { randomBytes } from "@stablelib/random";

const base64Encode = (bytes: Uint8Array): string => {
  const coder = new Coder();
  return coder.encode(bytes);
};

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  describe("createProof", () => {
    it("should create proof revealing single message from single message signature", () => {
      const messages = ["RmtnDBJHso5iSg=="];
      const bbsPublicKey = base64Decode(
        "wQLIhzBtR0MDmxo+OYoNF27fWcRVmGUzYDUC4iMU7qS53M8RIOuug10K7rygy2CGCJ7qLTBmT1HYU4na0uNrdvIjXtDZy7MWPmt9XVBvlmwxma2rFT5wnFrNXiepQsALFHYYdumiCO2dDvM5rOIyrnCDGNxwMb60w/JydBnJkf+OcYww68oSa9clZnKOXC96AAAAARNWR6dIznHmRL4DS+RiUbP4eMrx5skM0d1JZDssrYP/rSVeET+FMGhym5fRUg/m4w=="
      );
      const signature = base64Decode(
        "DWc6iJ/69RD+gw57DDbjx1bZhtuaFsRM1UCQOVc5KkBzVxghJP/yRrEPGEiYXpy+BVyn98dzXmFruQ9tiOd8ksmtLIQ8hZVxFICwp+BqnR0rTWPBEkM9+fglqa1/cAdhaGoM5gTezNCIeqxwmKMoKg=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: "0123456789",
        revealed: [0],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(380);
    });

    it("should create proof revealing all messages from multi-message signature", () => {
      const messages = ["J42AxhciOVkE9w==", "PNMnARWIHP+s2g==", "ti9WYhhEej85jw=="];

      const bbsPublicKey = base64Decode(
        "QNTo9lTZXfOKkWJO5Furc961teq1G9owfPIHqkMbURERbCW1S791w3FI9AI3TbQ8GGt8M3yrv+l7pHpunYoapk5rVkC5E7ayMFPWxg2vf2UbDhVxczn0+cJm82FptfWODO71c/5aMkr9MR2u+kcztWohg3V71JrptpomItbDx062ifg+qDy6ZG3cmZxIMM4uAAAAA4DsCC23t5+HWEP+TgOM7b99V7v1hKMiDnOszLEDoZ3cdI7qxlai225ULc/7DB14fxfurM3RHQiDafModRi5biRJg3oEZ3pKlPss+bNGpGnAHZn1uUOg/+hEOLbi5VRYwoKF6fJfIMCzAO3bGT3cmGKGd/a+UqeIs3MmVJbLgeE8/xD/iL/ywdXJombIErO08w=="
      );
      const signature = base64Decode(
        "ECU5n50Wio3vSbP0uFRyzV+sha40PlyRDcaUkF5BVtbiBZNI0aZSwJ5HWQk518vDCYhU582qfh5uqu5q37y3mWDqIA/ZmQB80zlwz878Z4Q933Q7CwsBsG26LebVst6hX/0LbNAjYLD/2exR1LTGsw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0, 1, 2],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(380); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing single message from multi-message signature", () => {
      const messages = ["J42AxhciOVkE9w==", "PNMnARWIHP+s2g==", "ti9WYhhEej85jw=="];

      const bbsPublicKey = base64Decode(
        "QNTo9lTZXfOKkWJO5Furc961teq1G9owfPIHqkMbURERbCW1S791w3FI9AI3TbQ8GGt8M3yrv+l7pHpunYoapk5rVkC5E7ayMFPWxg2vf2UbDhVxczn0+cJm82FptfWODO71c/5aMkr9MR2u+kcztWohg3V71JrptpomItbDx062ifg+qDy6ZG3cmZxIMM4uAAAAA4DsCC23t5+HWEP+TgOM7b99V7v1hKMiDnOszLEDoZ3cdI7qxlai225ULc/7DB14fxfurM3RHQiDafModRi5biRJg3oEZ3pKlPss+bNGpGnAHZn1uUOg/+hEOLbi5VRYwoKF6fJfIMCzAO3bGT3cmGKGd/a+UqeIs3MmVJbLgeE8/xD/iL/ywdXJombIErO08w=="
      );
      const signature = base64Decode(
        "ECU5n50Wio3vSbP0uFRyzV+sha40PlyRDcaUkF5BVtbiBZNI0aZSwJ5HWQk518vDCYhU582qfh5uqu5q37y3mWDqIA/ZmQB80zlwz878Z4Q933Q7CwsBsG26LebVst6hX/0LbNAjYLD/2exR1LTGsw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(444); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing multiple messages from multi-message signature", () => {
      const messages = ["J42AxhciOVkE9w==", "PNMnARWIHP+s2g==", "ti9WYhhEej85jw=="];

      const bbsPublicKey = base64Decode(
        "QNTo9lTZXfOKkWJO5Furc961teq1G9owfPIHqkMbURERbCW1S791w3FI9AI3TbQ8GGt8M3yrv+l7pHpunYoapk5rVkC5E7ayMFPWxg2vf2UbDhVxczn0+cJm82FptfWODO71c/5aMkr9MR2u+kcztWohg3V71JrptpomItbDx062ifg+qDy6ZG3cmZxIMM4uAAAAA4DsCC23t5+HWEP+TgOM7b99V7v1hKMiDnOszLEDoZ3cdI7qxlai225ULc/7DB14fxfurM3RHQiDafModRi5biRJg3oEZ3pKlPss+bNGpGnAHZn1uUOg/+hEOLbi5VRYwoKF6fJfIMCzAO3bGT3cmGKGd/a+UqeIs3MmVJbLgeE8/xD/iL/ywdXJombIErO08w=="
      );
      const signature = base64Decode(
        "ECU5n50Wio3vSbP0uFRyzV+sha40PlyRDcaUkF5BVtbiBZNI0aZSwJ5HWQk518vDCYhU582qfh5uqu5q37y3mWDqIA/ZmQB80zlwz878Z4Q933Q7CwsBsG26LebVst6hX/0LbNAjYLD/2exR1LTGsw=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0, 2],
      };

      const proof = createProof(request);
      expect(proof.length).toEqual(412); //TODO evaluate this length properly add a reason for this and some constants?
    });
  });

  describe("blsCreateProof", () => {
    it("should create proof revealing single message from single message signature", () => {
      const messages = ["uzAoQFqLgReidw=="];
      const blsPublicKey = base64Decode(
        "QxKqQn2uYPwHsDZoAN9G45nlDO3goV7NKLsUr0a/2PxtTYTeb6RpcbQdu4fXU082Ac1cegmB8COZFRCT6PDHkgTlTuxoLK6aoWlvD6VW7Vspo9vd3QI7jBkAK81CUVeV"
      );
      const signature = base64Decode(
        "ksCY3OEhXZbNydMVJqnJ3ygN0LkWU20X0/sdytoqpyzuy0koza+8IiGU27yGTaceRdxAQkwv8WQ6UI3x9gbWcI8632bGpyV4Fu23Uhaj4S4EgJyqV7FMJz7RrxasUmkyUAnGdjhzuSlRKAlXVcQNhg=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: "0123456789",
        revealed: [0],
      };

      const proof = blsCreateProof(request);
      expect(proof.length).toEqual(380);
    });

    it("should create proof revealing all messages from multi-message signature", () => {
      const messages = ["C+n1rPz1/tVzPg==", "h3x8cbySqC4rLA==", "MGf74ofGdRwNbw=="];

      const blsPublicKey = base64Decode(
        "ygMDbk5ItiEB/LNocLLRUNQfpDHUngTjD+YErlx+1/WPh5ZzcxX9LpsuTUslPMRZCXqBBowbq7rof3HuSLDwtcFET2kLt0qJTE8mjdnhOmEKTOl3vmEWylz3yH+jlBy1"
      );
      const signature = base64Decode(
        "AZOeIFhWATpeWCTm1NaJW2YjIaqEeOrlDcj+W9U7Jp+JSFMlga3hMjbJxaFkRFLwWJN9NbdpDYxGrePwRGAXzdQrcgcTRiU+f2QX00Xkrg0UfmWdnTBI6NJyYeeHtPO/6D0onuQst9sNdKY5AZPTqQ=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0, 1, 2],
      };

      const proof = blsCreateProof(request);
      expect(proof.length).toEqual(380); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing single message from multi-message signature", () => {
      const messages = ["uiSKIfNoO2rMrA==", "lMoHHrFx0LxwAw==", "wdwqLVm9chMMnA=="];

      const blsPublicKey = base64Decode(
        "V3FW9jlCSwPYOr7SVFXID0nytBj/e6wHoc8dK0Kn3pkckX2+UVKVgpCsFdSweJyvAc9wk6suCxmFJtfojw8BQmG3DtHbyHFWqgxIk9JyH2ZlR6fxtvZKkSlc0LDHHSN2"
      );
      const signature = base64Decode(
        "AgRmGhPpX/BhxmMHSgRjkjm8v2v7ZT+D4lLbOhQZkU1o8pic21gOPuP6tRBbNKByDWrM4usV+wQgncqA7KdbWbHl3u8PDZvoCsFs2JVs+nAJdK7/BMmAPu1bncufslXMdp9RjXCDYlHfxbYVKhQotQ=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0],
      };

      const proof = blsCreateProof(request);
      expect(proof.length).toEqual(444); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing multiple messages from multi-message signature", () => {
      const messages = ["uiSKIfNoO2rMrA==", "lMoHHrFx0LxwAw==", "wdwqLVm9chMMnA=="];

      const blsPublicKey = base64Decode(
        "V3FW9jlCSwPYOr7SVFXID0nytBj/e6wHoc8dK0Kn3pkckX2+UVKVgpCsFdSweJyvAc9wk6suCxmFJtfojw8BQmG3DtHbyHFWqgxIk9JyH2ZlR6fxtvZKkSlc0LDHHSN2"
      );
      const signature = base64Decode(
        "AgRmGhPpX/BhxmMHSgRjkjm8v2v7ZT+D4lLbOhQZkU1o8pic21gOPuP6tRBbNKByDWrM4usV+wQgncqA7KdbWbHl3u8PDZvoCsFs2JVs+nAJdK7/BMmAPu1bncufslXMdp9RjXCDYlHfxbYVKhQotQ=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: base64Encode(randomBytes(10)),
        revealed: [0, 2],
      };

      const proof = blsCreateProof(request);
      expect(proof.length).toEqual(412); //TODO evaluate this length properly add a reason for this and some constants?
    });
  });
});
