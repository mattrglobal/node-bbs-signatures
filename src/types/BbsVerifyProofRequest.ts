export interface BbsVerifyProofRequest {
  readonly proof: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly messages: string[];
  readonly revealed: number[];
  readonly messageCount: string[];
  readonly nonce: Uint8Array;
  readonly domainSeperationTag: string;
}