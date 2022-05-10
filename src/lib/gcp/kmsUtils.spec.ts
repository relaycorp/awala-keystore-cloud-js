import { KeyManagementServiceClient } from '@google-cloud/kms';

import { catchPromiseRejection } from '../../testUtils/promises';
import { GCPKeystoreError } from './GCPKeystoreError';
import { retrieveKMSPublicKey } from './kmsUtils';

describe('retrieveKMSPublicKey', () => {
  const KMS_KEY_VERSION_NAME = 'projects/foo/key/42';

  test('Specified key version name should be honored', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.objectContaining({ name: KMS_KEY_VERSION_NAME }),
      expect.anything(),
    );
  });

  test('Public key should be output DER-serialized', async () => {
    const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
    const kmsClient = makeKmsClient(derToPem(publicKeyDer));

    const publicKey = await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(publicKey).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
  });

  test('Public key export should time out after 500ms', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 500 }),
    );
  });

  test('Public key export should be retried up to 5 times', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ maxRetries: 5 }),
    );
  });

  test('API call errors should be wrapped', async () => {
    const callError = new Error('The service is down');
    const kmsClient = makeKmsClient(callError);

    const error = await catchPromiseRejection(
      retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient),
      GCPKeystoreError,
    );

    expect(error.message).toStartWith(`Failed to retrieve public key for ${KMS_KEY_VERSION_NAME}`);
    expect(error.cause()).toEqual(callError);
  });

  function makeKmsClient(
    publicKeyPemOrError: string | Error = 'pub key',
  ): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    jest.spyOn(kmsClient, 'getPublicKey').mockImplementation(() => {
      if (publicKeyPemOrError instanceof Error) {
        throw publicKeyPemOrError;
      }
      return [{ pem: publicKeyPemOrError }, undefined, undefined];
    });
    return kmsClient;
  }

  function derToPem(derBuffer: Buffer): string {
    const lines = derBuffer.toString('base64').match(/.{1,64}/g)!;
    return [`-----BEGIN PUBLIC KEY-----`, ...lines, `-----END PUBLIC KEY-----`].join('\n');
  }
});
