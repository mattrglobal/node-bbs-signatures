/**
 * A request to verify a BBS proof
 */
export interface BbsVerifyProofRequest {
  /**
   * The BBS proof to verify
   */
  readonly proof: Uint8Array;
  /**
   * Public key of the signer of the proof to verify
   */
  readonly publicKey: Uint8Array;
  /**
   * Revealed messages to verify (TODO maybe rename this field??)
   */
  readonly messages: string[];
  /**
   * Zero based indicies of the revealed messages in original signature
   */
  readonly revealed: number[];
  /**
   * Total count of the originally signed messages
   */
  readonly messageCount: number;
  /**
   * Nonce included in the proof for the un-revealed attributes (OPTIONAL)
   */
  readonly nonce: string;
  /**
   * Domain seperation featured in the proof (TODO do we need one for the sig and other for the proof?)
   */
  readonly domainSeperationTag: string;
}
