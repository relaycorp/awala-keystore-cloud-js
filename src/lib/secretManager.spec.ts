import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

process.env.GOOGLE_APPLICATION_CREDENTIALS = `${process.env.HOME}/Desktop/temp-awala-keystore-gcp-js-f136fe816a50.json`;

test('Please pass', async () => {
  const client = new SecretManagerServiceClient();

  const parent = 'projects/temp-awala-keystore-gcp-js', // Project for which to manage secrets.
    secretId = 'foobar2', // Secret ID.
    payload = 'hello world!'; // String source data.

  // Create the secret with automation replication.
  const [secret] = await client.createSecret({
    parent: parent,
    secret: {
      name: secretId,
      replication: {
        automatic: {},
      },
    },
    secretId,
  });

  console.info(`Created secret ${secret.name}`);

  // Add a version with a payload onto the secret.
  const [version] = await client.addSecretVersion({
    parent: secret.name,
    payload: {
      data: Buffer.from(payload, 'utf8'),
    },
  });

  console.info(`Added secret version ${version.name}`);

  // Access the secret.
  const [accessResponse] = await client.accessSecretVersion({
    name: version.name,
  });

  const responsePayload = (accessResponse!.payload!.data as Buffer).toString('utf8');
  console.info(`Payload: ${responsePayload}`);
});
