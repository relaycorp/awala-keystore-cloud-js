import { Datastore } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { derSerializePrivateKey, generateRSAKeyPair } from '@relaycorp/relaynet-core';

const KEY_FILE = `${process.env.HOME}/Desktop/temp-awala-keystore-gcp-js-f136fe816a50.json`;
const PROJECT_ID = 'temp-awala-keystore-gcp-js';

test('Data store', async () => {
  const datastore = new Datastore({
    projectId: PROJECT_ID,
    namespace: 'keystores',
    keyFilename: KEY_FILE,
  });

  const kmsClient = new KeyManagementServiceClient({ keyFilename: KEY_FILE });
  const kmsKey = kmsClient.cryptoKeyPath(PROJECT_ID, 'europe-west3', 'test1', 'the-key-name');

  const plaintext = await derSerializePrivateKey((await generateRSAKeyPair()).privateKey);
  console.log('Plaintext', plaintext.byteLength);

  console.time('all');
  console.time('crypto');
  const [encryptResponse] = await kmsClient.encrypt(
    {
      name: kmsKey,
      plaintext: plaintext,
    },
    { timeout: 600 },
  );
  console.timeEnd('crypto');

  console.log('ciphertext', (encryptResponse.ciphertext as Buffer).byteLength);

  const docRef = datastore.key(['privatekeys', 'id4']);

  console.time('doc');
  await datastore.save({
    key: docRef,
    excludeFromIndexes: ['foo', 'ciphertext'],
    data: { foo: 'bar', ciphertext: encryptResponse.ciphertext },
  });

  console.timeEnd('doc');
  console.timeEnd('all');
});
