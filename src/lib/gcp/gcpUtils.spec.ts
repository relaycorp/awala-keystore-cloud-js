import { catchPromiseRejection } from '../../testUtils/promises';
import { GCPKeystoreError } from './GCPKeystoreError';
import { wrapGCPCallError } from './gcpUtils';

describe('wrapGCPCallError', () => {
  const gcpError = new Error('Someone talked about Bruno');

  test('Successful calls should resolve', async () => {
    const resolvedValue = 42;

    await expect(wrapGCPCallError(Promise.resolve(resolvedValue), '')).resolves.toEqual(
      resolvedValue,
    );
  });

  test('Failed calls should be wrapped in custom error', async () => {
    await expect(wrapGCPCallError(Promise.reject(gcpError), '')).rejects.toBeInstanceOf(
      GCPKeystoreError,
    );
  });

  test('Wrapping exception should use specified error message', async () => {
    const errorMessage = 'The error message';

    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), errorMessage),
      GCPKeystoreError,
    );

    expect(error.message).toStartWith(`${errorMessage}:`);
  });

  test('Wrapped exception should be original one from GCP API client', async () => {
    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), ''),
      GCPKeystoreError,
    );

    expect(error.cause()).toEqual(gcpError);
  });
});
