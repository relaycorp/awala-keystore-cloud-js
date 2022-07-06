import { index, prop } from '@typegoose/typegoose';

@index({ privateAddress: 1 })
export class GcpIdentityKey {
  @prop({ required: true })
  public readonly privateAddress!: string;

  /**
   * The DER serialization of the respective public key.
   *
   * The main reason to cache it is to be able to populate the key algorithm on a private key,
   * not to save an API call to KMS (though that's still nice!).
   */
  @prop({ required: true })
  public readonly publicKey!: Buffer;

  /**
   * The KMS key id.
   *
   * This is stored in order to support the ability to migrate KMS keys within the same key ring.
   */
  @prop({ required: true })
  public readonly kmsKey!: string;

  @prop({ required: true })
  public readonly kmsKeyVersion!: number;
}
