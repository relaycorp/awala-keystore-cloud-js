import { CryptoKey } from 'webcrypto-core';

export class GcpKmsRsaPssPrivateKey extends CryptoKey {
  constructor(public kmsKeyVersionPath: string) {
    super();
    this.algorithm = { name: 'RSA-PSS' };
    this.type = 'private';
    this.usages = ['sign'];
    this.extractable = true; // The public key is exportable
  }
}
