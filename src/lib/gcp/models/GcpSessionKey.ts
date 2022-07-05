import { index, modelOptions, prop } from '@typegoose/typegoose';

@index({ id: 1, privateAddress: 1, peerPrivateAddress: 1 })
@modelOptions({ schemaOptions: { timestamps: { createdAt: 'creationDate', updatedAt: false } } })
export class GcpSessionKey {
  @prop({ required: true })
  public readonly keyId!: string;

  @prop({})
  public readonly creationDate!: Date;

  @prop({ required: true })
  public readonly privateAddress!: string;

  @prop({ required: true })
  public readonly peerPrivateAddress!: string | null;

  @prop({ required: true })
  public readonly privateKeyCiphertext!: Buffer;
}
