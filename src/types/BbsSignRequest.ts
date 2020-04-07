export interface BbsSignRequest {
  readonly privateKey: Uint8Array;
  readonly domainSeperationTag: Uint8Array;
  readonly messages: Uint8Array[];
}