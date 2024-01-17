export async function catchPromiseRejection<ErrorType extends Error>(
  promise: Promise<any>,
  errorClass: new () => ErrorType,
): Promise<ErrorType> {
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof errorClass)) {
      throw error;
    }
    return error as ErrorType;
  }
  throw new Error('Expected promise to throw');
}
