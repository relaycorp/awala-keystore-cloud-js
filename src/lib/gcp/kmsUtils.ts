import { KeyManagementServiceClient } from '@google-cloud/kms';

import { bufferToArrayBuffer } from '../utils/buffer';
import { sleep } from '../utils/timing';
import { wrapGCPCallError } from './gcpUtils';

/**
 * The official KMS library will often try to make API requests before the authentication with the
 * Application Default Credentials is complete, which will result in errors like "Exceeded
 * maximum number of retries before any response was received". We're working around that by
 * retrying a few times.
 */
export const KMS_REQUEST_OPTIONS = { timeout: 3_000, maxRetries: 10 };

export async function retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<ArrayBuffer> {
  const retrieveWhenReady = async () => {
    let key: string;
    try {
      key = await _retrieveKMSPublicKey(kmsKeyVersionName, kmsClient);
    } catch (err) {
      if (!isKeyPendingCreation(err as Error)) {
        throw err;
      }

      // Let's give KMS a bit more time to generate the key
      await sleep(500);
      key = await _retrieveKMSPublicKey(kmsKeyVersionName, kmsClient);
    }
    return key;
  };
  const publicKeyPEM = await wrapGCPCallError(retrieveWhenReady(), 'Failed to retrieve public key');
  const publicKeyDer = pemToDer(publicKeyPEM);
  return bufferToArrayBuffer(publicKeyDer);
}

async function _retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<string> {
  const [response] = await kmsClient.getPublicKey(
    { name: kmsKeyVersionName },
    {
      maxRetries: 3,
      timeout: 300,
    },
  );
  return response.pem!;
}

function isKeyPendingCreation(err: Error): boolean {
  const statusDetails = (err as any).statusDetails ?? [];
  const pendingCreationViolations = statusDetails.filter(
    (d: any) => 0 < d.violations.filter((v: any) => v.type === 'KEY_PENDING_GENERATION').length,
  );
  return !!pendingCreationViolations.length;
}

function pemToDer(pemBuffer: string): Buffer {
  const oneliner = pemBuffer.toString().replace(/(-----[\w ]*-----|\n)/g, '');
  return Buffer.from(oneliner, 'base64');
}
