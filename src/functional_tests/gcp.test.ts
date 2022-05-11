import { Datastore } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derSerializePrivateKey,
  derSerializePublicKey,
  SessionKeyPair,
} from '@relaycorp/relaynet-core';

import { constants, createVerify } from 'crypto';
import { DatastoreKinds } from '../lib/gcp/DatastoreKinds';
import { GcpKmsRsaPssPrivateKey } from '../lib/gcp/GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from '../lib/gcp/GcpKmsRsaPssProvider';
import { GCPPrivateKeyStore, KMSConfig } from '../lib/gcp/GCPPrivateKeyStore';
import { derPublicKeyToPem } from '../testUtils/asn1';
import { createKeyRingIfMissing } from './gcpUtils';
import { TEST_RUN_ID } from './utils';

if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  throw new Error('GOOGLE_APPLICATION_CREDENTIALS must be defined');
}
const GCP_LOCATION = process.env.GCP_LOCATION ?? 'europe-west3';

const KMS_KEY_RING = 'keystore-cloud-tests';
const kmsClient = new KeyManagementServiceClient();
let identityKeyName: string;
let sessionEncryptionKeyName: string;
beforeAll(async () => {
  const keyIdPrefix = `keystore-cloud-tests-${TEST_RUN_ID}`;
  const keyRingName = await createKeyRingIfMissing(KMS_KEY_RING, kmsClient, GCP_LOCATION);
  const destroyScheduledDuration = { seconds: 86400 }; // It should be at least a day :(

  const [createIdKeyResponse] = await kmsClient.createCryptoKey({
    cryptoKey: {
      destroyScheduledDuration,
      purpose: 'ASYMMETRIC_SIGN',
      versionTemplate: { algorithm: 'RSA_SIGN_PSS_2048_SHA256', protectionLevel: 'SOFTWARE' },
    },
    cryptoKeyId: `${keyIdPrefix}-id`,
    parent: keyRingName,
    // skipInitialVersionCreation: true, // TODO: REINSTATE
  });
  identityKeyName = createIdKeyResponse.name!; // Only set once key is actually created

  const [createSessionEncryptionKeyResponse] = await kmsClient.createCryptoKey({
    cryptoKey: {
      destroyScheduledDuration,
      purpose: 'ENCRYPT_DECRYPT',
      versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION', protectionLevel: 'SOFTWARE' },
    },
    cryptoKeyId: `${keyIdPrefix}-session`,
    parent: keyRingName,
    skipInitialVersionCreation: false,
  });
  sessionEncryptionKeyName = createSessionEncryptionKeyResponse.name!; // Only set once key is actually created
});
afterAll(async () => {
  if (identityKeyName) {
    await deleteAllKMSKeyVersions(identityKeyName);
  }
  if (sessionEncryptionKeyName) {
    await deleteAllKMSKeyVersions(sessionEncryptionKeyName);
  }
  await kmsClient.close();
});

const datastoreClient = new Datastore({ namespace: `keystores-${TEST_RUN_ID}` });
afterAll(async () => {
  await emptyDatastoreKind(DatastoreKinds.IDENTITY_KEYS);
  await emptyDatastoreKind(DatastoreKinds.SESSION_KEYS);
});

describe('Private key store', () => {
  test('Generate identity key pair', async () => {
    const store = new GCPPrivateKeyStore(kmsClient, datastoreClient, getKMSConfig());

    const { privateKey, privateAddress } = await store.generateIdentityKeyPair();

    const privateKeyRetrieved = await store.retrieveIdentityKey(privateAddress);

    expect(privateKeyRetrieved?.kmsKeyVersionPath).toEqual(
      (privateKey as GcpKmsRsaPssPrivateKey).kmsKeyVersionPath,
    );
  });

  test('Save and retrieve session key', async () => {
    const store = new GCPPrivateKeyStore(kmsClient, datastoreClient, getKMSConfig());
    const { privateKey, sessionKey } = await SessionKeyPair.generate();

    await store.saveUnboundSessionKey(privateKey, sessionKey.keyId);

    const privateKeyRetrieved = await store.retrieveSessionKey(sessionKey.keyId, '0deadbeef');
    await expect(derSerializePrivateKey(privateKeyRetrieved)).resolves.toEqual(
      await derSerializePrivateKey(privateKey),
    );
  });
});

describe('WebCrypto provider', () => {
  test('Sign with identity key', async () => {
    const store = new GCPPrivateKeyStore(kmsClient, datastoreClient, getKMSConfig());
    const provider = new GcpKmsRsaPssProvider(kmsClient);
    const { privateKey, publicKey } = await store.generateIdentityKeyPair();
    const plaintext = Buffer.from('this is the plaintext');

    const signature = await provider.sign(
      { name: 'RSA-PSS', saltLength: 32 } as any,
      privateKey,
      plaintext,
    );

    await expect(verifyAsymmetricSignature(publicKey, signature, plaintext)).resolves.toBeTrue();
  });

  async function verifyAsymmetricSignature(
    publicKey: CryptoKey,
    signature: ArrayBuffer,
    plaintext: Buffer,
  ): Promise<boolean> {
    const verify = createVerify('sha256');
    verify.update(plaintext);
    verify.end();

    const publicKeyDer = await derSerializePublicKey(publicKey);
    return verify.verify(
      { key: derPublicKeyToPem(publicKeyDer), padding: constants.RSA_PKCS1_PSS_PADDING },
      new Uint8Array(signature),
    );
  }
});

function getKMSConfig(): KMSConfig {
  const identityKeyId = kmsClient.matchCryptoKeyFromCryptoKeyName(identityKeyName) as string;
  const sessionEncryptionKeyId = kmsClient.matchCryptoKeyFromCryptoKeyName(
    sessionEncryptionKeyName,
  ) as string;
  return { identityKeyId, keyRing: KMS_KEY_RING, location: GCP_LOCATION, sessionEncryptionKeyId };
}

async function deleteAllKMSKeyVersions(kmsKeyName: string): Promise<void> {
  const [listResponse] = await kmsClient.listCryptoKeyVersions({ parent: kmsKeyName });
  await Promise.all(listResponse.map((k) => kmsClient.destroyCryptoKeyVersion({ name: k.name })));
}

async function emptyDatastoreKind(kind: DatastoreKinds): Promise<void> {
  const query = await datastoreClient.createQuery(kind).select('__key__');
  const [entities] = await datastoreClient.runQuery(query);
  const entityKeys = entities.map((e) => e[Datastore.KEY]);
  await datastoreClient.delete(entityKeys);
}
