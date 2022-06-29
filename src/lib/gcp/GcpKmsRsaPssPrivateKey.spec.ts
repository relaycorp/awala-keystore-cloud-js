import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';

const KMS_KEY_PATH = 'projects/foo/key/42';

const KMS_PROVIDER = new GcpKmsRsaPssProvider(null as any);

test('KMS key path should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, KMS_PROVIDER);

  expect(key.kmsKeyVersionPath).toEqual(KMS_KEY_PATH);
});

test('Crypto provider should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, KMS_PROVIDER);

  expect(key.provider).toBe(KMS_PROVIDER);
});

test('Algorithm should be RSA-PSS', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, KMS_PROVIDER);

  expect(key.algorithm.name).toEqual('RSA-PSS');
});

test('Usage should be "sign"', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, KMS_PROVIDER);

  expect(key.usages).toEqual(['sign']);
});

test('Key should be extractable', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, KMS_PROVIDER);

  expect(key.extractable).toBeTrue();
});
