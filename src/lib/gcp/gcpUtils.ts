import { GCPKeystoreError } from './GCPKeystoreError';

/**
 * Wrap GCP API call errors
 *
 * To provide a useful stack trace and error message, which we don't get with GCP library errors.
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
