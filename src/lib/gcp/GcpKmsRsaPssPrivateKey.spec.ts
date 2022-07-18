import { generateRSAKeyPair } from '@relaycorp/relaynet-core';

import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';

const KMS_KEY_PATH = 'projects/foo/key/42';
const KMS_PROVIDER = new GcpKmsRsaPssProvider(null as any);

let publicKey: CryptoKey;
beforeAll(async () => {
  const keyPair = await generateRSAKeyPair();
  publicKey = keyPair.publicKey;
});

test('KMS key path should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.kmsKeyVersionPath).toEqual(KMS_KEY_PATH);
});

test('Crypto provider should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.provider).toBe(KMS_PROVIDER);
});

test('Public key should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.publicKey).toBe(publicKey);
});

test('Hashing algorithm should be taken from public key', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.algorithm).toHaveProperty('hash.name', (publicKey.algorithm as any).hash.name);
});

test('Usage should be "sign"', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.usages).toEqual(['sign']);
});

test('Key should be extractable', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, publicKey, KMS_PROVIDER);

  expect(key.extractable).toBeTrue();
});
