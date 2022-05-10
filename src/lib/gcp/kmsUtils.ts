import { KeyManagementServiceClient } from '@google-cloud/kms';

import { bufferToArrayBuffer } from '../utils/buffer';
import { GCPKeystoreError } from './GCPKeystoreError';

export async function retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<ArrayBuffer> {
  let publicKeyPEM: string;
  try {
    const [exportResponse] = await kmsClient.getPublicKey(
      { name: kmsKeyVersionName },
      {
        maxRetries: 5, // Retry a few times in case the key was just created
        timeout: 500,
      },
    );
    publicKeyPEM = exportResponse.pem!;
  } catch (err) {
    throw new GCPKeystoreError(
      err as Error,
      `Failed to retrieve public key for ${kmsKeyVersionName}`,
    );
  }

  const publicKeyDer = pemToDer(publicKeyPEM);
  return bufferToArrayBuffer(publicKeyDer);
}

function pemToDer(pemBuffer: string): Buffer {
  const oneliner = pemBuffer.toString().replace(/(-----[\w ]*-----|\n)/g, '');
  return Buffer.from(oneliner, 'base64');
}
