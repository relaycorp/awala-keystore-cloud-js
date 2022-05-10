import { GCPKeystoreError } from './GCPKeystoreError';

/**
 * Wrap GCP API call errors
 *
 * To provide meaningful a useful stack trace and error message.
 *
 * @param callPromise
 * @param errorMessage
 */
export async function wrapGCPCallError<T>(
  callPromise: Promise<T>,
  errorMessage: string,
): Promise<T> {
  try {
    return await callPromise;
  } catch (err) {
    throw new GCPKeystoreError(err as Error, errorMessage);
  }
}
