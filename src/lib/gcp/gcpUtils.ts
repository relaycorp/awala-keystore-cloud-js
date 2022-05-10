import { GCPKeystoreError } from './GCPKeystoreError';

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
