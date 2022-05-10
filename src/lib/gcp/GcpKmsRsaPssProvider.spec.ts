import { KeyManagementServiceClient } from '@google-cloud/kms';
import { CryptoKey } from 'webcrypto-core';

import { mockSpy } from '../../testUtils/jest';
import { bufferToArrayBuffer } from '../utils/buffer';
import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import * as kmsUtils from './kmsUtils';

const ALGORITHM = { name: 'RSA-PSS', saltLength: 32 };

const PRIVATE_KEY = new GcpKmsRsaPssPrivateKey('/the/path/key-name');

describe('hashingAlgorithms', () => {
  test('Only SHA-256 and SHA-512 should be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    expect(provider.hashAlgorithms).toEqual(['SHA-256', 'SHA-512']);
  });
});

describe('onGenerateKey', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onGenerateKey()).rejects.toThrowWithMessage(
      GCPKeystoreError,
      'Key generation is unsupported',
    );
  });
});

describe('onImportKey', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onImportKey()).rejects.toThrowWithMessage(
      GCPKeystoreError,
      'Key import is unsupported',
    );
  });
});

describe('onSign', () => {
  const PLAINTEXT = bufferToArrayBuffer(Buffer.from('the plaintext'));

  test('Non-KMS key should be refused', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);
    const invalidKey = CryptoKey.create({ name: 'RSA-PSS' }, 'private', true, ['sign']);

    await expect(provider.sign(ALGORITHM, invalidKey, PLAINTEXT)).rejects.toThrowWithMessage(
      GCPKeystoreError,
      `Cannot sign with key of unsupported type (${invalidKey.constructor.name})`,
    );

    expect(kmsClient.asymmetricSign).not.toHaveBeenCalled();
  });

  test('Signature should be output', async () => {
    const expectSignature = Buffer.from('this is the signature');
    const kmsClient = makeKmsClient(expectSignature);
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    const signature = await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(signature).toEqual(expectSignature);
  });

  test('Correct key path should be used', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ name: PRIVATE_KEY.kmsKeyVersionPath }),
      expect.anything(),
    );
  });

  test('Correct plaintext should be passed', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.toSatisfy((req) => Buffer.from(req.data).equals(Buffer.from(PLAINTEXT))),
      expect.anything(),
    );
  });

  test('Request should time out after 500ms', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 500 }),
    );
  });

  describe('Algorithm parameters', () => {
    test.each([32, 64])('Salt length of %s should be accepted', async (saltLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);
      const algorithm = { ...ALGORITHM, saltLength };

      await provider.sign(algorithm, PRIVATE_KEY, PLAINTEXT);
    });

    test.each([20, 48])('Salt length of %s should be refused', async (saltLength) => {
      // 20 and 48 are used by SHA-1 and SHA-384, respectively, which are unsupported
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);
      const algorithm = { ...ALGORITHM, saltLength };

      await expect(provider.sign(algorithm, PRIVATE_KEY, PLAINTEXT)).rejects.toThrowWithMessage(
        GCPKeystoreError,
        `Unsupported salt length of ${saltLength} octets`,
      );
    });
  });

  function makeKmsClient(signature: Buffer = Buffer.from([])): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    const mockResponse = { signature };
    jest
      .spyOn(kmsClient, 'asymmetricSign')
      .mockImplementation(() => [mockResponse, undefined, undefined]);
    return kmsClient;
  }
});

describe('onVerify', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onVerify()).rejects.toThrowWithMessage(
      GCPKeystoreError,
      'Signature verification is unsupported',
    );
  });
});

describe('onExportKey', () => {
  const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
  const mockRetrieveKMSPublicKey = mockSpy(jest.spyOn(kmsUtils, 'retrieveKMSPublicKey'), () =>
    bufferToArrayBuffer(publicKeyDer),
  );

  test.each(['jwt', 'pkcs8', 'raw'] as readonly KeyFormat[])(
    '%s export should be unsupported',
    async (format) => {
      const provider = new GcpKmsRsaPssProvider(null as any);

      await expect(provider.onExportKey(format, PRIVATE_KEY)).rejects.toThrowWithMessage(
        GCPKeystoreError,
        'Private key cannot be exported',
      );

      expect(mockRetrieveKMSPublicKey).not.toHaveBeenCalled();
    },
  );

  test('SPKI format should be supported', async () => {
    const kmsClient = new KeyManagementServiceClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    const publicKey = await provider.exportKey('spki', PRIVATE_KEY);

    expect(publicKey).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
    expect(mockRetrieveKMSPublicKey).toHaveBeenCalledWith(PRIVATE_KEY.kmsKeyVersionPath, kmsClient);
  });

  test('Non-KMS key should be refused', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);
    const invalidKey = new CryptoKey();

    await expect(provider.onExportKey('spki', invalidKey)).rejects.toThrowWithMessage(
      GCPKeystoreError,
      'Key is not managed by KMS',
    );

    expect(mockRetrieveKMSPublicKey).not.toHaveBeenCalled();
  });
});
