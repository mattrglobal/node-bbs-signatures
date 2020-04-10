/**
 * A request verify a BBS signature for a set of messages
 */
export interface BbsVerifyRequest {
  /**
   * Public key of the signer of the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * Domain seperation tag used by the signature
   */
  readonly domainSeperationTag: string;
  /**
   * Raw signature value
   */
  readonly signature: Uint8Array;
  /**
   * Messages that were signed to produce the signature
   */
  readonly messages: string[];
}