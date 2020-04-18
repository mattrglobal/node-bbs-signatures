/**
 * A request to create a BBS proof from a supplied BBS signature
 */
export interface BbsCreateProofRequest {
  /**
   * BBS signature to generate the BBS proof from
   */
  readonly signature: Uint8Array;
  /**
   * Public key of the original signer of the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * The messages that were originally signed
   */
  readonly messages: readonly string[];
  /**
   * The zero based indicies of which messages to reveal
   */
  readonly revealed: readonly number[];
  /**
   * A nonce for the resulting proof
   */
  readonly nonce: string;
  /**
   * Domain seperation featured in the signature
   */
  readonly domainSeparationTag: string;
}
