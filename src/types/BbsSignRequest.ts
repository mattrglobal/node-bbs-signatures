/**
 * A request to create a BBS signature for a set of messages
 */
export interface BbsSignRequest {
  /**
   * Private/secret key of the signer
   */
  readonly secretKey: Uint8Array;
  /**
   * Domain seperation to feature in the signature
   */
  readonly domainSeperationTag: string;
  /**
   * Messages to sign
   */
  readonly messages: string[];
}