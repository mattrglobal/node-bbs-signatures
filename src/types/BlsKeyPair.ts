/**
 * A BLS 12-381 key pair
 */
export interface BlsKeyPair {
  /**
   * Raw public key value for the key pair
   */
  readonly publicKey: Uint8Array;
  /**
   * Raw secret/private key value for the key pair
   */
  readonly secretKey: Uint8Array;
}
