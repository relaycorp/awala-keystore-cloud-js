import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';

const KMS_KEY_PATH = 'projects/foo/key/42';

test('KMS key path should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH);

  expect(key.kmsKeyVersionPath).toEqual(KMS_KEY_PATH);
});

test('Algorithm should be RSA-PSS', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH);

  expect(key.algorithm.name).toEqual('RSA-PSS');
});

test('Usage should be "sign"', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH);

  expect(key.usages).toEqual(['sign']);
});

test('Key type should be private', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH);

  expect(key.type).toEqual('private');
});

test('Key should be extractable', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH);

  expect(key.extractable).toBeTrue();
});
