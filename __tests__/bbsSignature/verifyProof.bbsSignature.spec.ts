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

import { BbsVerifyProofRequest, verifyProof, blsVerifyProof, BbsCreateProofRequest } from "../../src";
import { Coder } from "@stablelib/base64";
import { createProof } from "../../lib";

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  describe("verifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", () => {
      const messages = ["KNK0ITRAF+NrGg=="];
      const bbsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pboZyjM38YgjaUBcjftZi5gb58Qz13XeRJpiuUHH06I7/1Eb8oVtIW5SGMNfKaqKhBAAAAAYPPztgxfWWw01/0SSug1oLfVuI4XUqhgyZ3rS6eTkOLjnyR3ObXb0XCD2Mfcxiv6w=="
      );
      const proof = base64Decode(
        "hDkH8srulv5qanhoI4vM9y4g1xTXUjsA04QBZGZ6OYcZN8I/SejmS1U89jrPzZ0/qFxjrUXSNOc1nzlQ84k9fCVPwJ6BsVmkCRzKzfLCoOSoe3PFBkrUWobQ7XlpP+yJqmVoefy1ECE9goWI9jamFZGEqqvZULGbCIKD81g+9dApcSVQQI4SrKe46mmV2spaAAAAdIkvTluLBkJGAPbieSGCwmUu4O5tiuy1liu/9rqWfTLCdqHCfOLSZEewcI/ouTslrQAAAAIywGSn1EndT+invB7sf3vjv5enDIhC/aMpyY9ZOF21S1/pJC0YiH6GNiWKCvb7rjib8MBwz3TDU2MFa7z1IfzEoG7aJiHfY0vDLUCEf81rXGMTxY/0ceaRYTlxUO6r30pJXHt04O6QZgGwl9G9+voQAAAAAkbYUeerG6ltVyg8Pm3Em1Bse1kZwmk8y/jpgU/S/4BWOe/H8+YTZB3ylwmZa6ZhJdk8g6zLwr6KQJbhQn8mBvU="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 1,
        messages,
        nonce: "v3bb/Mz+JajUdiM2URfZYcPuqxw=",
        revealed: [0],
      };

      expect(verifyProof(request).verified).toBeTruthy();
    });

    it("should verify proof with all messages revealed from multi message signature", () => {
      const messages = ["BVB6lAn912sz9Q==", "b45VqRkIo5R5Zw==", "yPqox0TIKS6vCA=="];
      const bbsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA=="
      );
      const proof = base64Decode(
        "h3Rn4cwHd2RwX/ZESqhxxFBFV2X3O+P1cuNVk/ZC8CVOzDXQpRIoZYE0Ux2up0TWgobGiXN3y46mvmj8wnMze7DQUKzgaMFERjhXZeiDhfAQOIsQqnQY0t+FUiSiOS3gmSjpak02wupc48e/PBopay5RM3DCWwc/9JENIlR8Xi6/pdnxkO96FUFnNL/F5mwuAAAAdI7sOIEZtkR80Fns81n00GtVzcpuRpN0QjwniggoKyC4TeXNcVDqGSvLllKLnKm7lgAAAAJzP+FK7nWiPt5vX/wF0S6b5Qv8+JW0EkLbb8SMp4hfD28qwCnQJv22DOcqWZHrPgyNmWwLyXYB74qjIsWBt/4wqa7cBc02ydJM50iTIg6QJ/PfAULF8uvm0J4emLind5A5BUO2KON5bpTawdrM8w6pAAAAAlAmx4V4qRfdXx3KfIi9kEFx/KGrC2E09xJaZyCQ8xLUDHAKZTctLm17Q2JKYk/F5xW39KPSH3fBuK/ghVJAe2Y="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 3,
        messages,
        nonce: "dVPpzuQtJVAZzAw73beWiXLtoT4=",
        revealed: [0, 1, 2],
      };

      expect(verifyProof(request).verified).toBeTruthy();
    });

    it("should verify proof with one message revealed from multi-message signature", () => {
      const messages = ["+FxEv3VLcNZ8sA==", "eI2RcRExnbP8hw==", "wll4zckqWAb0Kg=="];
      const bbsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA=="
      );
      const proof = base64Decode(
        "ikkpFypR34Mdn/wNP2RZtrqwcpoj+SjmR1uydDyEk8kInc/vf7oPbHrCtTiWa1mVrWEnCaGGZZmCcd8wRIWpcNQHWX66CF/UCYu2CUBW0kzIs1lG3fQq/5p0/0yuP0kvtYyAyovMUA1fx5i3kKEx+rkBBfQ1ErdCa073stgmPhHJZwBDICdLyXOsKe8vYtVbAAAAdLlW+LN+6vQWWi2GzciOe77qbZn8iu0pNSALjO/PzdWUT+1wNpDbsJ9ZbdhkX66AwQAAAAIouU0cL04T3rWhktuqqtQNEFbWGWArUp9xNvfgVyqAqhGDlt0bhcjaf+LggYOesc1813Qi/yZBudQGvL6GLbU3qmAvW5hyL3fp8I4d8f2cJKwol+CvJm+W4NJT82uZsRyZGdg/O37T1xOEKMn2zdy7AAAABE4lg9P3JxB9OIXLcE6iMIeJ/CZuLHCr6XUXd1zl4ywjEpJkxGtm9+BI3pQ38oJiI7Q04xlbisK52FE2EqqkQARiB1+0UFslkJHPPBFTHN6ZTZgraMHiC8X7cxNfjMhgxijz1ePrsfBlnZD2JKwvGTB9BvXhnOE5RsIdxaa9qW+T"
      );

      const revealedMessages = messages.slice(0, 1);

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 3,
        messages: revealedMessages,
        nonce: "NoWZhtX+u1wWLtUfPMmku1FtU2I=",
        revealed: [0],
      };

      expect(verifyProof(request).verified).toBeTruthy();
    });

    it("should not verify with bad nonce", () => {
      const messages = ["KNK0ITRAF+NrGg=="];
      const bbsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pboZyjM38YgjaUBcjftZi5gb58Qz13XeRJpiuUHH06I7/1Eb8oVtIW5SGMNfKaqKhBAAAAAYPPztgxfWWw01/0SSug1oLfVuI4XUqhgyZ3rS6eTkOLjnyR3ObXb0XCD2Mfcxiv6w=="
      );
      const proof = base64Decode(
        "pIeLfsSfc1OiVl+pl/JhNuUCU4QgxbWrh65HGF3E+O/RvlZbWxXwQaFlT6FNZjpQqxbiTRy11m4eU4IUyjLUVbJM37Q0WNAHi8ZtHgRzet4WvXAceUAd/uMTMAXkYYcKtejUTHHNznH4lXDfvX0Cwhd9K0jNKtOoH6/cU2UoWs3xXmIU8VzAlK2D5USD0XugAAAAdJVWlU2ZGa5oqSfBbW9r4d2nS/iF/0mC47gK5vAprhIA7cZg2g+a4WvgkGa7O9rr/gAAAAJmNzGETKIxJgvAECZDbURQzj+ty9MXZjja8m1tuy8DCEzM7hSK8BLL63mvSfiPYwuzSPrTAGNHVx2o2+OqXLZyt0ZAl+ObXg7lo5wOtjBrhvh/duOon2bkr+H3lSg9KGsjy4K9Eg8CkHnbKQnJ3R21AAAAAg1ueBGiTp1ucUqlD62vuEiBmR01q16EkdjLB4TYPfBcZ0GeQ3P7t+3ar0k+CZcoVyLktXjwmtsLxcjntzbHyN0="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 1,
        messages,
        nonce: "bad",
        revealed: [0],
      };

      expect(verifyProof(request).verified).toBeFalsy();
    });

    it("should not verify with a message that wasn't signed", () => {
      // Expects messages to be ["Message1", "Message2", "Message3", "Message4"];
      const messages = ["BadMessage1", "Message2", "Message3", "Message4"];
      const bbsPublicKey = base64Decode(
        "S+bRoSJJOet/8hKDpXFV+8TXzg0gPcD64lMFtIUzhYtMJAnNqfJRJnFIS0Vs2VC8AK6MBa6TYgILMqVv4RTSEl3H66mOF6jrEOHelKGlkJCNY8u3bI2aXrmqTkhnjxck"
      );
      const proof = base64Decode(
        "hB0FDeTQc5KEm00wG5HNRvCJ6uoA9flPeTv08PGQct5URoP+mxn6K4hmgRFUMPDZGGspwrc4fCs5SDF+O0nbSyHNLRemj8IMsoruTqhLWrqDWxDhdDDoPYZ4uYoOGIuTBoJqxkv9uFjDRiRnINGvcIJ+QV2iwzwesAHcFmQnxOu/UBEm4XMCDiU93HABZn1uAAAAdJbRgZKb314nZ/PcSUH79GQacq9OAtiOfrCxyaVL5Nt8wXmoY0ri9cBF3XzrySjY7QAAAAIfsXyZmQFTmcislP+mYAk+9nl3V7hTQnc6VIz1Vzayyyses57/fYftogle+iFyMP9kfMujXAf0AOx268LFfZnuA4+PYfY+mH1l/ieGMkvaTFRrfi+sfxFX14wCTH8Qy7Z4+DjTUIPIBGwqCMiBWZ3ZAAAABUtLeqN3HfQNyXQNf7A5MKx00tYvssxatlylAv+lmU2cD2ke0dY7hltzXgGFJ8LjtPIe6uMlZdmdu6+l/0IHK4RGYhEYGwZ4NHu6mlydV/7XiFpJKd9vtmfGBYXU6nXHkxGZ3I0D3FfFFA30B/UFBYqGZ7EKFIObMmvmcQWbTFkkHYAlabXh2RAVSlTmNL+NrIu1LbLW0CBExF4f+H8kZmM="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 4,
        messages,
        nonce: "0123456789",
        revealed: [0],
      };
      expect(verifyProof(request).verified).toBeFalsy();
    });
  });

  it("should not verify with revealed message that was supposed to be hidden", () => {
    const messages = ["Message1", "Message2", "Message3", "Message4"];
    const signature = base64Decode(
      "j46NB7z6EBzD6q8bwBfzNYmjab3LPVoU7swcxO4qukq+qx0TrJhmo1TAW5UpDIFWSdb5kgWLAda2giwW4GImPTl8yWwIBJksnfT7zD8nonsvVaJh15/YrQ/n5KlknD4OtLTquji9RJK1U/xWzERHtA=="
    );
    const bbsPublicKey = base64Decode(
      "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbosOXSMyokWdxxfboF4VchlaYCp6XTOpMx4eyDYmBELxlb71I+QX1EGjnMnqAWZALAAAABKw+umnxXMNjIO3KXpByQV8QUtZdLanMRAho0zu8eUHbpCa8+v+Hlz+ziXN62rCmToaOrGXpFkFlUDFdw3gMUlYoWo40rF5sy4v8gci5xS1SHYnz3SAeUJ/wzT3RKEv3PbIxyz5fihZJFqz1XdL7KK2I8eNtnTU7L3xFrsFQ4YTkl2bQSS/cix8zYW3ane6WGIbfFUf4yFDsXmDT0THKKoly245B3nW/s5VfMDDaqWfsK4HThMgm9bOyeOuNultvNg=="
    );
    const nonce = "0123456789";

    const proofRequest: BbsCreateProofRequest = {
      signature,
      publicKey: bbsPublicKey,
      messages,
      revealed: [0],
      nonce,
    };
    const proof = createProof(proofRequest);

    let proofMessages = ["BadMessage9"];
    let request = {
      proof,
      publicKey: bbsPublicKey,
      messageCount: 4,
      messages: proofMessages,
      nonce,
      revealed: [0],
    };

    expect(verifyProof(request).verified).toBeFalsy();

    proofMessages = ["Message1"];
    request = {
      proof,
      publicKey: bbsPublicKey,
      messageCount: 4,
      messages: proofMessages,
      nonce,
      revealed: [0],
    };
    expect(verifyProof(request).verified).toBeTruthy();
  });

  describe("blsVerifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", () => {
      const messages = ["KnYAbm0fw3mlUA=="];
      const blsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb"
      );
      const proof = base64Decode(
        "uLUIaKQlI5UDCclFeai7Yk1iR4a+zuabPwBOWkynevty/UnG8Yh44BGfYOz3SDp5l/V91GOGtPcKLm8WNZ5zqUfNIUogiA3xPVgNbA+XFicb8bFA50ds+x/epkzjg/rWoKSgEbVGYk2QkwhC6Sw5azfVszE+GeVYO1JCOzWLo3pd4HRaycTSQr343WxOGKrDAAAAdKFr7Bju9OOPr2mYqpBAN30kMeaXeRuBIWFjlgz0gM5vrXPiKKrQttWBofwodTj7WQAAAAI6aMOilYHommgDQRuOxKEKUV85fv8e/P2J2A1ux6i00zcng3C0YSZgm41KQo0xLi1wea2LK6AHvtpSlFtVo3d/mYqOoWfYPPvZi9lLTEGF6oB8aW1WmsUOULHuq+l+/3mCUAcaRrr0NiBdGSnVirdyAAAAAgggNDwzvJHeWdgNGCjV08gqkM1f9QF9IVM2kCMP2Wf5IrCXdQQLHeHaGyCJXabx7xmoz1fCirpmRZ0cgUzs9Gk="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: blsPublicKey,
        messageCount: 1,
        messages,
        nonce: "4OS3nji2HNReo3QPHrdlxjOf8gc=",
        revealed: [0],
      };

      expect(blsVerifyProof(request).verified).toBeTruthy();
    });

    it("should verify proof with all messages revealed from multi message signature", () => {
      const messages = ["ODLpUKee6nyz7g==", "v2zteJajIyIh5Q==", "x64hA8TTn4gYXg=="];
      const blsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb"
      );
      const proof = base64Decode(
        "tWvkoPcKldhrYWyyrTOXZz7ss+ZBNmS74lZtIbmtBRwpV/vhGDOb1dxH2a4V0iV8gOwAP2d4VaLFkPdgKhqmzpzEMGGR/tWubkhc8QJe4nq5/QHTn+6U2/aAVYl83IegpaFciHD8YUQ4wrw7CsXy6I8ll32yGNEdbkOCGF87jOk2TdHNROh9UlCE+kLd5wObAAAAdLJE81paBSnXwlqZl/sLRxiVxP08x8oTbGrMU4qS2vY59dGsqsEGehBlOY0FEppLAAAAAAI61eqzpebd6zEJbyZXRUQTP08F4nSbYgMCmxvRwdJziBKM8241kOQ0dtiyG6tUIc70RGIa1r3SWUGmztADduLqtq9vNmCOGvnerzyrJTFDLv9+9pdkFoNe3BjaeDjBiYx8PpxXJntwHlFRBwNWRBZ7AAAAAlt9QML66pbXrdlzg0Y0df5SHSh8s2AyJ0EzF0xwI12wE6bBDRRxynZJa+qE9EZCQJVCAfsonUfy7IWSYFT70Gw="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: blsPublicKey,
        messageCount: 3,
        messages,
        nonce: "ujMevaaq2n7Cg3ZLzXktqT/WRgM=",
        revealed: [0, 1, 2],
      };

      expect(blsVerifyProof(request).verified).toBeTruthy();
    });

    it("should verify proof with one message revealed from multi-message signature", () => {
      const messages = ["8NhsJO/MKxO74A==", "0noLBcl29ASJ2w==", "eMPpY348vqGDNA=="];
      const blsPublicKey = base64Decode(
        "qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb"
      );
      const proof = base64Decode(
        "iWXfi7djxnPI5mKEI4f9m2kZlxhY6gfLqfpr+J2pGtVqZ2hWOy6gG+LrrA48di/drKodNASanxuTsxEYJp6Myt0D3nkPFXRYvO/aVhbj9KxA5jLETllFkW4bsIIvfNm8rIzIADD86Eo5k26SxrMm443u1fjemXTisJcZGKlpUlMtdqiP+iq9OwMTpVzRIyQLAAAAdI2m23MeCc/9ScbWRCr3yKAtLWsl3eVfB8b6VgyHvYi2Y0cv5VVleCQOBbwd0OdELQAAAAIh6SOoJaWeIK/i1HTNyaUvf+w9VNr+rl9fTW09RzTBRyth9Wjhp1EHqo6ZNsQjp8YObDP392d9uvu4RD+whU4MjViO/uoCRgimJS3lfJRm+GnLhBtxoiqLjOghubaaq1N3RWNePdCINrXwyQFGXkpoAAAABEdAKgNfsnt30MBdD1GgF0OyTAOOMckW2700GQG28ke1CafTwADG/I7l068bYgDlhNsspBL3p4MGmw+Y5wq3HKtPhdvGTrOpvaWHWhze9ACIKY77C5kyjXndlexMcjak+xdDp7FXWU8QCTddXdQ8xl5mWmjOSlDKxVmgdNIvcpFS"
      );

      const revealedMessages = messages.slice(0, 1);

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: blsPublicKey,
        messageCount: 3,
        messages: revealedMessages,
        nonce: "I03DvFXcpVdOPuOiyXgcBf4voAA=",
        revealed: [0],
      };

      expect(blsVerifyProof(request).verified).toBeTruthy();
    });

    it("should not verify with bad nonce", () => {
      const messages = ["KnYAbm0fw3mlUA=="];
      const blsPublicKey = base64Decode(
        "x45gpyN9ryZHcdlbJCKrM6WAPI6BggO97nmTcimnXwFA7AeMf54x7atqH0BvxV4UA3f7DcWHpq0HEytVwin7pd/AZXjexfTynNgUgVdd/xkcRdwKCgBMnEx5R7csAGVm"
      );
      const proof = base64Decode(
        "FagknzSill0LJXtGH5BzCq4c6xzq2Tlkz2miS/wH3KHELHXVRDAh6gA0JEXJZ1wxDmE7E48gWfNnWYhXLddWwXCqN5U9/Y/YvHskEpphr4r9YllNpvTm64nDfPcGwdwqEouJLdW3KV4FfQxWVBDwP1I5XJoyKuQ6y/mHeJKbpSPfgYIiWX4RyIr6bfkY3X8oAAAAdAEHfTDBk/agRv6zYVllWmPcVB5dmimVexdCio8iRukFlCnUj6MYFSt4vEnUg6iDngAAAAJOeYWML03bKoZGhmKmvgLroVR0Z8S6rjwX5c4vhmm2ejoupjMkwZJwuv5LeSTlEH2zNqanYGIybJ70qxG10ObChGLxINGqCI7fQucyXT71x50ql3PIxhKBbKveZ5MB9L33DOR5mHFvpxKrTy8gP4DZAAAAAkl1ZauWisDi0mCTy0Wqt41+q4++n8DafY2/kItHGYQgABvFjN9Ued6TmhtxIrYuHV48936xnaZaNfavGrXR6ds="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: blsPublicKey,
        messageCount: 1,
        messages,
        nonce: "bad",
        revealed: [0],
      };

      expect(blsVerifyProof(request).verified).toBeFalsy();
    });
  });
});
