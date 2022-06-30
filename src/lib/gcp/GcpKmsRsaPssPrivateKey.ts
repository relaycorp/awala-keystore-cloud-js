import { PrivateKey } from '@relaycorp/relaynet-core';

import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';

export class GcpKmsRsaPssPrivateKey extends PrivateKey {
  constructor(
    public kmsKeyVersionPath: string,
    public readonly publicKey: CryptoKey,
    provider: GcpKmsRsaPssProvider,
  ) {
    super(provider);

    this.algorithm = publicKey.algorithm;
    this.usages = ['sign'];
    this.extractable = true; // The public key is exportable
  }
}
