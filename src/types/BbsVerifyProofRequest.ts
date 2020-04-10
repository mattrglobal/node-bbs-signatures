export interface BbsVerifyProofRequest {
  readonly proof: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly messages: readonly string[];
  readonly revealed: readonly number[];
  readonly messageCount: readonly string[];
  readonly nonce: Uint8Array;
  readonly domainSeperationTag: string;
}
