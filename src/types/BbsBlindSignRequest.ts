export interface BbsBlindSignRequest {
  readonly commitment: Uint8Array;
  readonly proofOfCommitment: Uint8Array;
  readonly challengeHash: Uint8Array;
  readonly secretKey: Uint8Array;
  readonly messages: string[];
  readonly messageCount: string[];
  readonly known: number[];
  readonly nonce: Uint8Array;
  readonly domainSeperationTag: string;
}