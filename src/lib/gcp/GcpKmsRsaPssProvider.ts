import { KeyManagementServiceClient } from '@google-cloud/kms';
import { CryptoKey, RsaPssProvider } from 'webcrypto-core';

import { bufferToArrayBuffer } from '../utils/buffer';
import { GcpKmsError } from './GcpKmsError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_SALT_LENGTHS: readonly number[] = [
  256 / 8, // SHA-256
  512 / 8, // SHA-512
];

export class GcpKmsRsaPssProvider extends RsaPssProvider {
  constructor(protected kmsClient: KeyManagementServiceClient) {
    super();

    // See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
    this.hashAlgorithms = ['SHA-256', 'SHA-512'];
  }

  public async onGenerateKey(): Promise<CryptoKeyPair> {
    throw new GcpKmsError('Key generation is unsupported');
  }

  public async onImportKey(): Promise<CryptoKey> {
    throw new GcpKmsError('Key import is unsupported');
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer> {
    if (format !== 'spki') {
      throw new GcpKmsError('Private key cannot be exported');
    }
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new GcpKmsError('Key is not managed by KMS');
    }

    const [exportResponse] = await this.kmsClient.getPublicKey(
      { name: key.kmsKeyVersionPath },
      { timeout: 500 },
    );
    const publicKeyDer = pemToDer(exportResponse.pem!);
    return bufferToArrayBuffer(publicKeyDer);
  }

  public async onSign(
    algorithm: RsaPssParams,
    key: CryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new GcpKmsError(`Cannot sign with key of unsupported type (${key.constructor.name})`);
    }

    if (!SUPPORTED_SALT_LENGTHS.includes(algorithm.saltLength)) {
      throw new GcpKmsError(`Unsupported salt length of ${algorithm.saltLength} octets`);
    }

    const [response] = await this.kmsClient.asymmetricSign(
      {
        data: new Uint8Array(data),
        name: key.kmsKeyVersionPath,
      },
      { timeout: 500 },
    );

    return response.signature as Uint8Array;
  }

  public async onVerify(): Promise<boolean> {
    throw new GcpKmsError('Signature verification is unsupported');
  }
}

function pemToDer(pemBuffer: string): Buffer {
  const oneliner = pemBuffer.toString().replace(/(-----[\w ]*-----|\n)/g, '');
  return Buffer.from(oneliner, 'base64');
}
