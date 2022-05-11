export interface IdentityKeyEntity {
  /**
   * The KMS key id.
   *
   * This is stored in order to support the ability to migrate KMS keys within the same key ring.
   */
  readonly key: string;

  readonly version: string;
}

export interface SessionKeyEntity {
  readonly creationDate: Date;
  readonly privateKeyCiphertext: Buffer;
  readonly peerPrivateAddress?: string;
}
