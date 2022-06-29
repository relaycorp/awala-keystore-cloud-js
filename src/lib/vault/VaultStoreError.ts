import { CloudKeystoreError } from '../CloudKeystoreError';

export class VaultStoreError extends CloudKeystoreError {
  constructor(message: string, responseErrorMessages?: readonly string[]) {
    const finalErrorMessage = responseErrorMessages
      ? `${message} (${responseErrorMessages.join(', ')})`
      : message;
    super(finalErrorMessage);
  }
}
