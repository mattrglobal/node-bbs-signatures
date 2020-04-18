/**
 * A request to create a BBS signature that features blinded/commited messages
 */
export interface BbsBlindSignRequest {
  /**
   * The resulting commitment of the blinded messages to sign
   */
  readonly commitment: Uint8Array;
  /**
   * The secret key of the signer
   */
  readonly secretKey: Uint8Array;
  /**
   * The known messages to sign
   */
  readonly messages: readonly string[];
  /**
   * Domain seperation tag to feature in the signature
   */
  readonly domainSeparationTag: string;
  /**
   * Total number of messages to sign both known and blinded
   */
  readonly messageCount: number;
}
