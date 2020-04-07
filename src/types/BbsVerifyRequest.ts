export interface BbsVerifyRequest {
  readonly publicKey: Uint8Array;
  readonly domainSeperationTag: Uint8Array;
  readonly signature: Uint8Array;
  readonly messages: Uint8Array[];
}