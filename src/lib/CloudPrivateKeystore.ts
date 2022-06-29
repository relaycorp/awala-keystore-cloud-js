import { PrivateKeyStore } from '@relaycorp/relaynet-core';

export abstract class CloudPrivateKeystore extends PrivateKeyStore {
  public abstract close(): Promise<void>;
}
