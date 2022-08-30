import { index, modelOptions, prop } from '@typegoose/typegoose';

@index({ keyId: 1, nodeId: 1, peerId: 1 })
@modelOptions({ schemaOptions: { timestamps: { createdAt: 'creationDate', updatedAt: false } } })
export class GcpSessionKey {
  @prop({ required: true })
  public readonly keyId!: string;

  @prop({})
  public readonly creationDate!: Date;

  @prop({ required: true })
  public readonly nodeId!: string;

  @prop()
  public readonly peerId?: string;

  @prop({ required: true })
  public readonly privateKeyCiphertext!: Buffer;
}
