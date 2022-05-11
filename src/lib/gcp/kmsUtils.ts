import { KeyManagementServiceClient } from '@google-cloud/kms';

import { bufferToArrayBuffer } from '../utils/buffer';
import { wrapGCPCallError } from './gcpUtils';

export async function retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<ArrayBuffer> {
  const [exportResponse] = await wrapGCPCallError(
    kmsClient.getPublicKey(
      { name: kmsKeyVersionName },
      {
        maxRetries: 10, // Retry a few times in case the key was just created
        timeout: 250,
      },
    ),
    `Failed to retrieve public key for ${kmsKeyVersionName}`,
  );
  const publicKeyDer = pemToDer(exportResponse.pem!);
  return bufferToArrayBuffer(publicKeyDer);
}

function pemToDer(pemBuffer: string): Buffer {
  const oneliner = pemBuffer.toString().replace(/(-----[\w ]*-----|\n)/g, '');
  return Buffer.from(oneliner, 'base64');
}
