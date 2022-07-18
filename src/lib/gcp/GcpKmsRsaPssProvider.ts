import { KeyManagementServiceClient } from '@google-cloud/kms';
import { derSerializePublicKey } from '@relaycorp/relaynet-core';
import { calculate as calculateCRC32C } from 'fast-crc32c';
import { CryptoKey, RsaPssProvider } from 'webcrypto-core';

import { bufferToArrayBuffer } from '../utils/buffer';
import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { wrapGCPCallError } from './gcpUtils';
import { KMS_REQUEST_OPTIONS } from './kmsUtils';

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_SALT_LENGTHS: readonly number[] = [
  256 / 8, // SHA-256
  512 / 8, // SHA-512
];

export class GcpKmsRsaPssProvider extends RsaPssProvider {
  constructor(public kmsClient: KeyManagementServiceClient) {
    super();

    // See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
    this.hashAlgorithms = ['SHA-256', 'SHA-512'];
  }

  public async onGenerateKey(): Promise<CryptoKeyPair> {
    throw new GCPKeystoreError('Key generation is unsupported');
  }

  public async onImportKey(): Promise<CryptoKey> {
    throw new GCPKeystoreError('Key import is unsupported');
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer> {
    if (format !== 'spki') {
      throw new GCPKeystoreError('Private key cannot be exported');
    }
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new GCPKeystoreError('Key is not managed by KMS');
    }
    const keySerialized = await derSerializePublicKey(key.publicKey);
    return bufferToArrayBuffer(keySerialized);
  }

  public async onSign(
    algorithm: RsaPssParams,
    key: CryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new GCPKeystoreError(
        `Cannot sign with key of unsupported type (${key.constructor.name})`,
      );
    }

    if (!SUPPORTED_SALT_LENGTHS.includes(algorithm.saltLength)) {
      throw new GCPKeystoreError(`Unsupported salt length of ${algorithm.saltLength} octets`);
    }

    return this.kmsSign(Buffer.from(data), key);
  }

  public async onVerify(): Promise<boolean> {
    throw new GCPKeystoreError('Signature verification is unsupported');
  }

  private async kmsSign(plaintext: Buffer, key: GcpKmsRsaPssPrivateKey): Promise<ArrayBuffer> {
    const plaintextChecksum = calculateCRC32C(plaintext);
    const [response] = await wrapGCPCallError(
      this.kmsClient.asymmetricSign(
        { data: plaintext, dataCrc32c: { value: plaintextChecksum }, name: key.kmsKeyVersionPath },
        KMS_REQUEST_OPTIONS,
      ),
      'KMS signature request failed',
    );

    if (response.name !== key.kmsKeyVersionPath) {
      throw new GCPKeystoreError(`KMS used the wrong key version (${response.name})`);
    }
    if (!response.verifiedDataCrc32c) {
      throw new GCPKeystoreError('KMS failed to verify plaintext CRC32C checksum');
    }
    const signature = response.signature as Buffer;
    if (calculateCRC32C(signature) !== Number(response.signatureCrc32c!.value)) {
      throw new GCPKeystoreError('Signature CRC32C checksum does not match one received from KMS');
    }
    return bufferToArrayBuffer(signature);
  }
}
