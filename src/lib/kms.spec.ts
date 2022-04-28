import { KeyManagementServiceClient } from '@google-cloud/kms';

test('KMS', async () => {
  // Instantiates a client
  const client = new KeyManagementServiceClient({
    keyFilename: `${process.env.HOME}/Desktop/temp-awala-keystore-gcp-js-f136fe816a50.json`,
  });

  // Build the parent location name
  const locationName = client.locationPath('temp-awala-keystore-gcp-js', 'europe-west1');

  async function createKeyRing() {
    const [keyRing] = await client.createKeyRing({
      parent: locationName,
      keyRingId: 'test-id-from-gcp-shell',
    });

    console.log(`Created key ring: ${keyRing.name}`);
    return keyRing;
  }

  return createKeyRing();
});
