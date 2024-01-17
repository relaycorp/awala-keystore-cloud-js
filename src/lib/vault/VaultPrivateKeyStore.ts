/* tslint:disable:max-classes-per-file */

import {
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  SessionPrivateKeyData,
} from '@relaycorp/relaynet-core';
import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';

import { base64Decode, base64Encode } from '../utils/base64';
import {
  KeyDataDecoded,
  KeyDataEncoded,
  SessionKeyDataDecoded,
  SessionKeyDataEncoded,
} from './keyData';
import { VaultStoreError } from './VaultStoreError';
import { CloudPrivateKeystore } from '../CloudPrivateKeystore';

export class VaultPrivateKeyStore extends CloudPrivateKeystore {
  protected readonly axiosClient: AxiosInstance;

  constructor(vaultUrl: string, vaultToken: string, kvPath: string) {
    super();

    const baseURL = buildBaseVaultUrl(vaultUrl, kvPath);
    this.axiosClient = axios.create({
      baseURL,
      headers: { 'X-Vault-Token': vaultToken },
      httpAgent: new HttpAgent({ keepAlive: true }),
      httpsAgent: new HttpsAgent({ keepAlive: true }),
      timeout: 3000,
      validateStatus: null as any,
    });

    // Sanitize errors to avoid leaking sensitive data, which apparently is a feature:
    // https://github.com/axios/axios/issues/2602
    this.axiosClient.interceptors.response.use(undefined, async (error) =>
      Promise.reject(new Error(error.message)),
    );
  }

  public async retrieveIdentityKey(nodeId: string): Promise<CryptoKey | null> {
    const keyData = await this.retrieveData(`i-${nodeId}`);
    if (!keyData?.privateKey) {
      return null;
    }
    return derDeserializeRSAPrivateKey(keyData.privateKey);
  }

  public async close(): Promise<void> {
    // There are no resources to release
  }

  public async saveIdentityKey(nodeId: string, privateKey: CryptoKey): Promise<void> {
    const keySerialized = await derSerializePrivateKey(privateKey);
    await this.saveData(keySerialized, `i-${nodeId}`);
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<void> {
    await this.saveData(keySerialized, `s-${keyId}`, { peerId, nodeId });

    if (!peerId) {
      // The key is unbound, so upsert it as the unbound key for the node
      await this.saveData(keySerialized, `s-node-${nodeId}`);
    }
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const keyData = await this.retrieveData(`s-${keyId}`);
    if (!keyData) {
      return null;
    }
    return {
      keySerialized: keyData.privateKey,
      peerId: (keyData as SessionKeyDataDecoded).peerId,
      nodeId: (keyData as SessionKeyDataDecoded).nodeId,
    };
  }

  private async saveData(
    keySerialized: Buffer,
    keyId: string,
    metadata: Omit<KeyDataEncoded, 'privateKey'> | null = null,
  ): Promise<void> {
    const keyBase64 = base64Encode(keySerialized);
    const data: KeyDataEncoded = { privateKey: keyBase64, ...(metadata ?? {}) };
    const response = await this.axiosClient.post(`/${keyId}`, { data });
    if (response.status !== 200 && response.status !== 204) {
      throw new VaultStoreError(
        `Vault returned a ${response.status} response`,
        response.data.errors,
      );
    }
  }

  protected override async retrieveLatestUnboundSessionKeySerialised(
    nodeId: string,
  ): Promise<Buffer | null> {
    const data = await this.retrieveData(`s-node-${nodeId}`);
    return data?.privateKey ?? null;
  }

  private async retrieveData(keyId: string): Promise<KeyDataDecoded | null> {
    const response = await this.axiosClient.get(`/${keyId}`);

    if (response.status === 404) {
      return null;
    }
    if (response.status !== 200) {
      throw new VaultStoreError(
        `Vault returned a ${response.status} response`,
        response.data.errors,
      );
    }

    const vaultData = response.data.data.data as KeyDataEncoded;
    return {
      peerId: (vaultData as SessionKeyDataEncoded).peerId,
      nodeId: (vaultData as SessionKeyDataEncoded).nodeId,
      privateKey: base64Decode(vaultData.privateKey),
    };
  }
}

function buildBaseVaultUrl(vaultUrl: string, kvPath: string): string {
  const sanitizedVaultUrl = vaultUrl.replace(/\/+$/, '');
  const sanitizedKvPath = kvPath.replace(/^\/+/, '').replace(/\/+/, '');
  return `${sanitizedVaultUrl}/v1/${sanitizedKvPath}/data`;
}
