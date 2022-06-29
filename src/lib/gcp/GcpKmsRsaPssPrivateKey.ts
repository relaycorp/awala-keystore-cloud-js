import { PrivateKey } from '@relaycorp/relaynet-core';

import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';

export class GcpKmsRsaPssPrivateKey extends PrivateKey {
  constructor(public kmsKeyVersionPath: string, provider: GcpKmsRsaPssProvider) {
    super(provider);

    this.algorithm = { name: 'RSA-PSS' };
    this.usages = ['sign'];
    this.extractable = true; // The public key is exportable
  }
}
