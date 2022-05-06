export async function catchPromiseRejection<ErrorType extends Error>(
  promise: Promise<any>,
  errorClass: new () => ErrorType,
): Promise<ErrorType> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(errorClass);
    return error as ErrorType;
  }
  throw new Error('Expected promise to throw');
}
