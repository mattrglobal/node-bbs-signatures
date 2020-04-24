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

import { BbsVerifyProofRequest } from "../../src";
import { Coder } from "@stablelib/base64";
import { verifyProof, blsVerifyProof } from "../../src/bbsSignature";

const base64Decode = (string: string): Uint8Array => {
  const coder = new Coder();
  return coder.decode(string);
};

describe("bbsSignature", () => {
  describe("verifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", () => {
      const messages = ["KNK0ITRAF+NrGg=="];
      const bbsPublicKey = base64Decode(
        "h47St8J+WsxY637WBnXJ+iLIbcA6hyVStxUUk3cq4coVEidovUUovGmLGVH9HXqmAG7Ruam2OBe5L6beoTgh3XH/dUbDg2NKEsjzcAxHAdkBwzsNrgsGdvAf256ptUNEGWK+oCJTwtOcCTtXPOMPLNZcruqsco0AQ3TEn/vL/p2fa/qUurd8LXm7Q1jV2EyiAAAAAQelag0xZRbCLV5ZYhb3m/sstmTB/Y3AtAe5YH+4/Qek/vwBwPziXC0JX318F/+fgQ=="
      );
      const proof = base64Decode(
        "gumaTSrAopa8OltvsU1ZkPRuilINIKBYRCgBSRroijBF++axv6O4Fg6+e15GarGhmEbBubJ70hMKCyHUXzdK3bODkV7NAg7JLFtHqisq47h7vtn2Qr/zggZdRQr5UFM5A7L2sC0AmxnNAA1o3Q2E4krFy9+RENG/3NVxMM2siy0pm+1LG+dTVSNNyPv81H73AAAAdAcynwBL2JoVZTTdbwqSqb5C6CNKCqk9jmECD3CcCcy/QLyJbOznMC/m4K4UKPJTiAAAAAJWXLpMW4bHlLnVIVQsT1JNK9gkM8rs51GiclcsPmfv3j8CzScx+i9JaMx7RHUWaVNWyKZJ2HSR1nxAn5VJ0FVkkT4bvs9APqEFhF7MT3lLdV7knsoYskTfrgV90NU/IEKsOFaMNudsh3wt6agfEGSJAAAAAjkuMTpcoA2OQF5cKYUIklBz/kppcqeJX/PeB3P9dLX/HeVzSP8MloBvFYmk2e87lfjH+ZktrnMx/MtqHEnD2f8="
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
        "FX8AP5nD+6ehanwfSq8yHJv963i6HuFAO7kn+RJNmZBbIJ4c/95LqkoEAyF42oxKAwkIooyYmMUBV9Flvp/gtNF2gssvCFfUwjfVi/xO0iFsaVa2/E7w9ModRprLkTyalr2+1lR68kAbVdi8GtrIcn3FsCS1rDfpVB6vYORYTRjabdOeUKB+udVNZHBnWxAsAAAAAwNL2vMLqf/WwSykx6S/03+xXzTvdA/p3da5mkbmgEOYZhR2zz8aGUTNRpJupK1JFpnRZHgGy6tiDb7HdtqiTXVMJ1403GwejAi1iAHnGq9fRltviKWuXU6i2XqrO6hV2Rmk2q7HEXW5iA1ebGvYT94N4mFrdiKSgzReQfXrCFGNVqKzd2MWg5i+K9XraUA/yA=="
      );
      const proof = base64Decode(
        "FnYGEqMwmCGBpMJr0Vgz7+mKhm0bzaYOD9lfy/AAelJcyR/2utinzdNo0V9kyTw7hdo9i/qiMJMxcctEG2eJjvPYhHxUN5GLfCCj1PBEEPfwhNxWbo5hZDphr7Fdoji1Cqf8Tyocd2aCeLyROXWk8g2wiMUJSWLaeOF4cj+vMoZ73PVdYw8fazsDsVUfYIK1AAAAdI92k3PzlxvhIsa+9X5PHR5vzOq+S05L6AxgB8E/K9dhdYxkBlM61Xzdiuc/6EdFoQAAAAJF48aG+4tnmDdlNn9OQ+27y9zCDEkP8Tb22PW4QvCiOBijsxgUZxRSiUTxgudqZFMYvhFpKlSy4CE7HO/pLNLcFh0BFQRLTvOSGLyURy61EiL5mvv1Kxf/u6EIuaWDDbo2NTHbl4hFWySlzPMvzGYzAAAAAkSnWGhK52PH7VlY6C8e0PDLqBkwL8+ZWELiNnqy7/EjSOR2aoD/kV8ob2NthFlQJZmbT3y0SRxJIuveBeQs/5Y="
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
        "UqbLAcOAAAYxFkCfqBQSFWWFPFe33MsyGN+tZ4Sa+RcvLZZbrvJqA78mF6jdVYX6A4vuTeQFTzIRGxaFRXHgsa6HCsAcekquYqfpwsFxOoaeOuKZe1JC0+AS2pOqa+F2iXwSmtH3vAjtra955z1d8FohnooTqwgnM5JE4YTX5vamW344OWdQ/57OHn5ncT5UAAAAA5ATVdfWX2nvZqHgdtuKu9mDIxM0+Y5vR4GkZoyuYf7OzDKICWy07lrciNtsBuYrNBiEAdtDjNtr46Qb9FMnq3Vci3+ehfuGxf0ijd8KRBe5kAm5QOHjeC2Tq0cfFh7zTpXBqr9oMKUFEzhbYQRXcNV4Ctx7dJ6+aoMLsSehr5E+sq9YjqIpnDnHlbf2IG0qvA=="
      );
      const proof = base64Decode(
        "lbV+CVLpSHSHgfxNdh8f/VxC8wcG097rmpH7F1WgWvO/7bQUToaH/9sTTwfM+rOQEWIbvP0dg+iN+0t3nIWh/omkiVPu2JfFQ2W7FEvIayjG0fYudqb8qjEiM1wIMbEEjm4j+eV/Mwh6pl5uFC3LLJ4s0oqoncdn5KfnDXROKmh8+W+AQRnvV1Aa/835BlxRAAAAdJebhu2vN4Pwz7YNEsxnsePuMPuFrP1EzAVLRGn+W9HxgS/JDxc+TeXNVWH3N/I45AAAAAIhRB7jHKRFtiNd6iLjheI5BCG0BgMRqbTjns6eBCslx2i+jLK1kUAFoDeEtHGTfdQ/c3qMiF9Y634jjod5jFoKFjV5xZNt1fe1fIDI8gpKit+60d2O9tol0Uz08VMOJOzE5z904y7dZJbz660FtIBhAAAABBAX3h/4aE/sv+ylPRmCNxX6ZcngVtDQ8O4cQTYjcnv9K8S5DbB1JfEJw4ZS7a0hgthPAd+k2ekgTuzbe81Mbntti3sJAxwMkI7jekbGMDY0GePUE1NUpJNnvqgeFSypngZcVYBISq+DRy4wl0Ws6hoY2IEqJhR2xPfk0XqtnFC8"
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
        "h47St8J+WsxY637WBnXJ+iLIbcA6hyVStxUUk3cq4coVEidovUUovGmLGVH9HXqmAG7Ruam2OBe5L6beoTgh3XH/dUbDg2NKEsjzcAxHAdkBwzsNrgsGdvAf256ptUNEGWK+oCJTwtOcCTtXPOMPLNZcruqsco0AQ3TEn/vL/p2fa/qUurd8LXm7Q1jV2EyiAAAAAQelag0xZRbCLV5ZYhb3m/sstmTB/Y3AtAe5YH+4/Qek/vwBwPziXC0JX318F/+fgQ=="
      );
      const proof = base64Decode(
        "gumaTSrAopa8OltvsU1ZkPRuilINIKBYRCgBSRroijBF++axv6O4Fg6+e15GarGhmEbBubJ70hMKCyHUXzdK3bODkV7NAg7JLFtHqisq47h7vtn2Qr/zggZdRQr5UFM5A7L2sC0AmxnNAA1o3Q2E4krFy9+RENG/3NVxMM2siy0pm+1LG+dTVSNNyPv81H73AAAAdAcynwBL2JoVZTTdbwqSqb5C6CNKCqk9jmECD3CcCcy/QLyJbOznMC/m4K4UKPJTiAAAAAJWXLpMW4bHlLnVIVQsT1JNK9gkM8rs51GiclcsPmfv3j8CzScx+i9JaMx7RHUWaVNWyKZJ2HSR1nxAn5VJ0FVkkT4bvs9APqEFhF7MT3lLdV7knsoYskTfrgV90NU/IEKsOFaMNudsh3wt6agfEGSJAAAAAjkuMTpcoA2OQF5cKYUIklBz/kppcqeJX/PeB3P9dLX/HeVzSP8MloBvFYmk2e87lfjH+ZktrnMx/MtqHEnD2f8="
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
  });

  describe("blsVerifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", () => {
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
        nonce: "4OS3nji2HNReo3QPHrdlxjOf8gc=",
        revealed: [0],
      };

      expect(blsVerifyProof(request).verified).toBeTruthy();
    });

    it("should verify proof with all messages revealed from multi message signature", () => {
      const messages = ["ODLpUKee6nyz7g==", "v2zteJajIyIh5Q==", "x64hA8TTn4gYXg=="];
      const blsPublicKey = base64Decode(
        "S378kH1eZ1oF8qn9DShyjGlslPwJs9lmAXuLUlZgoJEX2iypbFp3g102Jp/ROGzfENKHTUuR+4i93YXWor51QUzhpLWR1DmqHrwLZ/7j2cRkF5w79YvlhjsxnaMmKUBV"
      );
      const proof = base64Decode(
        "i05XCmsC7ZwTA27Y/dgHoUMaJRxKeTl2EHobrBQ7zZ116pCCTFD9Q/TLXF/1HxdyhDwunbiZ3C2uHSPmwIdjzouQFnA1dGFGPPq6WjKeMT1pMxsIFHi/GLQKfmRmsH42iDXB5VFq9VJWZpH/rsFxd3wtukm0bfvGTJb4lbE3s6nc1vQSXxW0KGdg5Wq5X+lsAAAAdBemRZhVKupkO0BTMFOHNGEEgp+kBbK1eCQNxnW94J9juQs7W7miW3/UXhA/0t0aPgAAAAI1SYOeEUeKuHErQUezytejAZI+iUhng8J/uc22c54jVx404p9YjV2PjvO77pr6pRkJ36BAA/War3fCIzIj52HwhFio4NXr/MINt1lXSOFrhRJxXQBGhh/12G9G0pHkEyUWbpkzppBz5H7CLZoWj27GAAAAAjPav87VgpL3GupoMnlL15zAS1+wvyq2wGdyglqhbbvSM/CnUTIfGO3Gg+dHXLUQDXuMNj6ovMax/BJSx5KPQUw="
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
        "VWZvI9wN8ZXNjXeEBp/nEi4/gG5YF+WftUUgjYEv8+eaSlRfC7OzI1DcMdAIjF8nFJONCcrYzzhrJXHryhNd7ukjm7/Inmlcp1oZxL8N0BZOLF1pS5h0HVcAOptuinDI"
      );
      const proof = base64Decode(
        "mNmq1EEswvY7LnGPxMM+K5g0kAW1ZyJnll25VH17Dotw+BmMjJ5lLJMHSSlWmtjvi0qiFDr5QrkJQQ5+2F4SmvJy0erAB8fKt3Pi7DvPl5ELZXFJBHQBNUVxkSPjEZLJFJwJdBhCtMeuNPpHpCLPsdhWkgFR19TdWoXVSIGzfQGtXgk74Trpy5OVer7WKmEfAAAAdI68+AZMNNrJnC6/LDKLGSbh7Umpd5ZTtVV6S823bOeudX94FIk3Pa+U8IOes0Nq0wAAAAIzTRgz+Mkc7xVqfMJEdi4TGKXAQMlvcF2/g/l9MqgPQBxA+Bc9CbF9hiln/XHPOXqu9OZw8ovv9i4nzpZRaWPxmV8HowKijoEhcRoxdFEi/HBOZdODWrXPNGE+U5oZetlAf2ktG6UEbQJ9Z7Aw/S1LAAAABFWG4W41OkyIyxKi162i8lagHaYTvrlPG/JI4GwgDZ6OJf0pkVabyrCEfrwONOU+aDFhNFHU48NhkQvHyLFUPe5PCXh+5JfltMm3pSlAIMqYOStWzUTuExfa9Ti3LpryfThvjSqWibqmVpBCK3AjS1XpMRyYnQxcurp2TAk2BqAq"
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

    // it("should not verify with bad nonce", () => {
    //   const messages = ["KNK0ITRAF+NrGg=="];
    //   const blsPublicKey = base64Decode(
    //     "h47St8J+WsxY637WBnXJ+iLIbcA6hyVStxUUk3cq4coVEidovUUovGmLGVH9HXqmAG7Ruam2OBe5L6beoTgh3XH/dUbDg2NKEsjzcAxHAdkBwzsNrgsGdvAf256ptUNEGWK+oCJTwtOcCTtXPOMPLNZcruqsco0AQ3TEn/vL/p2fa/qUurd8LXm7Q1jV2EyiAAAAAQelag0xZRbCLV5ZYhb3m/sstmTB/Y3AtAe5YH+4/Qek/vwBwPziXC0JX318F/+fgQ=="
    //   );
    //   const proof = base64Decode(
    //     "gumaTSrAopa8OltvsU1ZkPRuilINIKBYRCgBSRroijBF++axv6O4Fg6+e15GarGhmEbBubJ70hMKCyHUXzdK3bODkV7NAg7JLFtHqisq47h7vtn2Qr/zggZdRQr5UFM5A7L2sC0AmxnNAA1o3Q2E4krFy9+RENG/3NVxMM2siy0pm+1LG+dTVSNNyPv81H73AAAAdAcynwBL2JoVZTTdbwqSqb5C6CNKCqk9jmECD3CcCcy/QLyJbOznMC/m4K4UKPJTiAAAAAJWXLpMW4bHlLnVIVQsT1JNK9gkM8rs51GiclcsPmfv3j8CzScx+i9JaMx7RHUWaVNWyKZJ2HSR1nxAn5VJ0FVkkT4bvs9APqEFhF7MT3lLdV7knsoYskTfrgV90NU/IEKsOFaMNudsh3wt6agfEGSJAAAAAjkuMTpcoA2OQF5cKYUIklBz/kppcqeJX/PeB3P9dLX/HeVzSP8MloBvFYmk2e87lfjH+ZktrnMx/MtqHEnD2f8="
    //   );

    //   const request: BbsVerifyProofRequest = {
    //     proof,
    //     publicKey: blsPublicKey,
    //     messageCount: 1,
    //     messages,
    //     nonce: "bad",
    //     revealed: [0],
    //   };

    //   expect(blsVerifyProof(request).verified).toBeFalsy();
    // });
  });
});
