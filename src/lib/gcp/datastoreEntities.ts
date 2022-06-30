export interface IdentityKeyEntity {
  /**
   * The KMS key id.
   *
   * This is stored in order to support the ability to migrate KMS keys within the same key ring.
   */
  readonly key: string;

  readonly version: string;

  /**
   * The DER serialization of the respective public key.
   *
   * The main reason to cache it is to be able to populate the key algorithm on a private key,
   * not to save an API call to KMS (though that's still nice!).
   */
  readonly publicKey: Buffer;
}

export interface SessionKeyEntity {
  readonly creationDate: Date;
  readonly privateKeyCiphertext: Buffer;
  readonly privateAddress: string;
  readonly peerPrivateAddress?: string;
}
