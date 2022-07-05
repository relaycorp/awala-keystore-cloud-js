import { index, prop } from '@typegoose/typegoose';

@index({ privateAddress: 1 })
export class GcpIdentityKey {
  @prop({ required: true })
  public readonly privateAddress!: string;

  @prop({ required: true })
  public readonly publicKey!: Buffer;

  @prop({ required: true })
  public readonly kmsKey!: string;

  @prop({ required: true })
  public readonly kmsKeyVersion!: number;
}
