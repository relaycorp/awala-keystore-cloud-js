import { CryptoKey } from 'webcrypto-core';

export class GcpKmsPrivateKey extends CryptoKey {
  constructor(public kmsKeyName: string, usage: 'sign' | 'decrypt') {
    super();
    this.type = 'private';
    this.usages = [usage];
    this.extractable = false;
  }
}
