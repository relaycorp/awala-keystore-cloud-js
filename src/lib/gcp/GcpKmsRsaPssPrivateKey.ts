import { RsaPssPrivateKey } from '@relaycorp/relaynet-core';

import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';

export class GcpKmsRsaPssPrivateKey extends RsaPssPrivateKey {
  constructor(
    public kmsKeyVersionPath: string,
    public readonly publicKey: CryptoKey,
    provider: GcpKmsRsaPssProvider,
  ) {
    super((publicKey.algorithm as any).hash.name, provider);
  }
}
