import { KeyManagementServiceClient } from '@google-cloud/kms';

export async function createKeyRingIfMissing(
  keyRingId: string,
  kmsClient: KeyManagementServiceClient,
  location: string,
): Promise<string> {
  const project = await kmsClient.getProjectId();
  const keyRingName = kmsClient.keyRingPath(project, location, keyRingId);
  try {
    await kmsClient.getKeyRing({ name: keyRingName });
  } catch (err) {
    if ((err as any).code !== 5) {
      throw err;
    }

    // Key ring was not found
    const locationPath = kmsClient.locationPath(project, location);
    await kmsClient.createKeyRing({ parent: locationPath, keyRingId });
  }
  return keyRingName;
}
