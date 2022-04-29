import { GcpKmsPrivateKey } from './GcpKmsPrivateKey';

const KMS_KEY_NAME = 'the key name';

test('KMS key name should be honored', async () => {
  const key = new GcpKmsPrivateKey(KMS_KEY_NAME, 'sign');

  expect(key.kmsKeyName).toEqual(KMS_KEY_NAME);
});

describe('Usage', () => {
  test('Sign should be supported', async () => {
    const key = new GcpKmsPrivateKey(KMS_KEY_NAME, 'sign');

    expect(key.usages).toEqual(['sign']);
  });

  test('Decrypt should be supported', async () => {
    const key = new GcpKmsPrivateKey(KMS_KEY_NAME, 'decrypt');

    expect(key.usages).toEqual(['decrypt']);
  });
});

test('Key type should be private', async () => {
  const key = new GcpKmsPrivateKey(KMS_KEY_NAME, 'sign');

  expect(key.type).toEqual('private');
});

test('Key should not be extractable', async () => {
  const key = new GcpKmsPrivateKey(KMS_KEY_NAME, 'sign');

  expect(key.extractable).toBeFalse();
});
