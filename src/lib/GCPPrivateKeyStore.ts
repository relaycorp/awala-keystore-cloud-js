import { PrivateKeyStore, SessionPrivateKeyData } from '@relaycorp/relaynet-core';

export class GCPPrivateKeyStore extends PrivateKeyStore {
  protected retrieveIdentityKeySerialized(privateAddress: string): Promise<Buffer | null> {
    throw new Error('implement ' + privateAddress);
  }

  protected retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    throw new Error('implement ' + keyId);
  }

  protected saveIdentityKeySerialized(
    privateAddress: string,
    keySerialized: Buffer,
  ): Promise<void> {
    throw new Error('implement ' + privateAddress + keySerialized);
  }

  protected saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    peerPrivateAddress?: string,
  ): Promise<void> {
    throw new Error('implement ' + keyId + keySerialized + peerPrivateAddress);
  }
}
