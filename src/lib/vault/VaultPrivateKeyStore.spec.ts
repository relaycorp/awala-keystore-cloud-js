import {
  derSerializePrivateKey,
  generateRSAKeyPair,
  getIdFromIdentityKey,
  KeyStoreError,
  SessionKeyPair,
  UnknownKeyError,
} from '@relaycorp/relaynet-core';
import axios, { AxiosRequestConfig } from 'axios';
import * as http from 'http';
import * as https from 'https';

import { catchPromiseRejection } from '../../testUtils/promises';
import { base64Encode } from '../utils/base64';
import { VaultPrivateKeyStore } from './VaultPrivateKeyStore';

describe('VaultPrivateKeyStore', () => {
  const mockAxiosCreate = jest.spyOn(axios, 'create');
  beforeEach(() => {
    mockAxiosCreate.mockReset();
  });
  afterAll(() => {
    mockAxiosCreate.mockRestore();
  });

  const stubVaultUrl = 'http://localhost:8200';
  const stubKvPath = 'pohttp-private-keys';
  const stubVaultToken = 'letmein';

  const nodeId = '0deadc0de';
  const peerId = '0deadbeef';

  let sessionKeyPair: SessionKeyPair;
  let sessionKeyIdHex: string;
  beforeAll(async () => {
    sessionKeyPair = await SessionKeyPair.generate();
    sessionKeyIdHex = sessionKeyPair.sessionKey.keyId.toString('hex');
  });

  describe('constructor', () => {
    describe('Axios client', () => {
      const mockResponseInterceptorUse = jest.fn();
      beforeEach(() => {
        mockAxiosCreate.mockReturnValue({
          interceptors: {
            // @ts-ignore
            response: {
              use: mockResponseInterceptorUse,
            },
          },
        });
      });

      let axiosCreateCallOptions: AxiosRequestConfig;
      beforeEach(() => {
        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

        expect(mockAxiosCreate).toBeCalledTimes(1);
        axiosCreateCallOptions = mockAxiosCreate.mock.calls[0][0] as AxiosRequestConfig;
      });

      test('Keep alive should be used', () => {
        expect(axiosCreateCallOptions.httpsAgent).toBeInstanceOf(https.Agent);
        expect(axiosCreateCallOptions.httpsAgent).toHaveProperty('keepAlive', true);

        expect(axiosCreateCallOptions.httpAgent).toBeInstanceOf(http.Agent);
        expect(axiosCreateCallOptions.httpAgent).toHaveProperty('keepAlive', true);
      });

      test('A timeout of 3 seconds should be used', () => {
        expect(axiosCreateCallOptions).toHaveProperty('timeout', 3000);
      });

      test('Base URL should include Vault URL and KV path', () => {
        expect(axiosCreateCallOptions).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Base URL should be normalized', () => {
        mockAxiosCreate.mockClear();

        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(`${stubVaultUrl}/`, stubVaultToken, `/${stubKvPath}/`);

        expect(mockAxiosCreate.mock.calls[0][0]).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Vault token should be included in the headers', () => {
        expect(axiosCreateCallOptions).toHaveProperty('headers.X-Vault-Token', stubVaultToken);
      });

      test('Status validation should be disabled', async () => {
        expect(axiosCreateCallOptions).toHaveProperty('validateStatus', null);
      });

      test('An error interceptor that removes sensitive data should be registered', async () => {
        const stubError = { message: 'Denied', sensitive: 's3cr3t' };

        expect(mockResponseInterceptorUse).toBeCalledTimes(1);

        const responseInterceptorCallArgs = mockResponseInterceptorUse.mock.calls[0];
        const errorInterceptor = responseInterceptorCallArgs[1];
        try {
          await errorInterceptor(stubError);
          fail('Expected interceptor to reject');
        } catch (error) {
          expect(error).toHaveProperty('message', stubError.message);
          expect(error).not.toHaveProperty('sensitive');
        }
      });
    });
  });

  describe('Saving', () => {
    const mockAxiosClient = { post: jest.fn(), interceptors: { response: { use: jest.fn() } } };
    beforeEach(() => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValue({ status: 204 });

      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient as any);
    });

    test('Identity key should be generated', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const { privateKey, id } = await store.generateIdentityKeyPair();

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/i-${id}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(privateKey)),
      );
    });

    test('Unbound session key should be stored', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/s-${sessionKeyIdHex}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
      );
      expect(postCallArgs[1]).toHaveProperty('data.peerId', undefined);
    });

    test('Bound session key should be stored', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
        peerId,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/s-${sessionKeyIdHex}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
      );
      expect(postCallArgs[1]).toHaveProperty('data.peerId', peerId);
    });

    test('Axios errors should be wrapped', async () => {
      const axiosError = new Error('Denied');
      mockAxiosClient.post.mockRejectedValue(axiosError);
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await catchPromiseRejection(store.generateIdentityKeyPair(), KeyStoreError);

      expect(error.cause()).toEqual(axiosError);
    });

    test('A 200 OK response should be treated as success', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 200 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.generateIdentityKeyPair();
    });

    test('A 204 No Content response should be treated as success', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.generateIdentityKeyPair();
    });

    test('A non-200/204 response should raise an error', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 400, data: {} });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await catchPromiseRejection(store.generateIdentityKeyPair(), KeyStoreError);

      expect(error.cause()?.message).toEqual('Vault returned a 400 response');
    });

    test('Error messages in 40X/50X responses should be included in error', async () => {
      const errorMessages: ReadonlyArray<any> = ['foo', 'bar'];
      mockAxiosClient.post.mockResolvedValue({ status: 400, data: { errors: errorMessages } });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await catchPromiseRejection(store.generateIdentityKeyPair(), KeyStoreError);

      expect(error.cause()?.message).toEqual(
        `Vault returned a 400 response (${errorMessages.join(', ')})`,
      );
    });
  });

  describe('Retrieval', () => {
    const mockAxiosClient = { get: jest.fn(), interceptors: { response: { use: jest.fn() } } };
    beforeEach(async () => {
      mockAxiosClient.get.mockReset();

      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient as any);
    });

    test('Existing identity key should be returned', async () => {
      const senderKeyPair = await generateRSAKeyPair();
      const senderPrivateKey = senderKeyPair.privateKey;
      const senderId = await getIdFromIdentityKey(senderKeyPair.publicKey);
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            privateKey: base64Encode(await derSerializePrivateKey(senderPrivateKey)),
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.retrieveIdentityKey(senderId);

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/i-${senderId}`);
      await expect(derSerializePrivateKey(privateKey!)).resolves.toEqual(
        await derSerializePrivateKey(senderPrivateKey),
      );
    });

    test('Existing unbound session key should be returned', async () => {
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            nodeId,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.retrieveUnboundSessionKey(
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/s-${sessionKeyIdHex}`);
      await expect(derSerializePrivateKey(privateKey)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Existing bound session key should be returned', async () => {
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            peerId,
            nodeId,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.retrieveSessionKey(
        sessionKeyPair.sessionKey.keyId,
        nodeId,
        peerId,
      );

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/s-${sessionKeyIdHex}`);
      await expect(derSerializePrivateKey(privateKey)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Session key should not be returned if bound to another recipient', async () => {
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            peerId: `not-${peerId}`,
            nodeId,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Session key should not be returned if owned by different owner', async () => {
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            peerId,
            nodeId: `not-${nodeId}`,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Non-existing identity key should raise an UnknownKeyError', async () => {
      mockAxiosClient.get.mockResolvedValue({ status: 404 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(store.retrieveIdentityKey(nodeId)).resolves.toBeNull();
    });

    test('Non-existing session key should raise an UnknownKeyError', async () => {
      mockAxiosClient.get.mockResolvedValue({ status: 404 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Axios errors should be wrapped', async () => {
      const originalError = new Error('Denied');
      mockAxiosClient.get.mockRejectedValue(originalError);
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toThrowWithMessage(
        KeyStoreError,
        `Failed to retrieve key: ${originalError.message}`,
      );
    });

    test('Any status other than 200 or 404 should raise a KeyStoreError', async () => {
      mockAxiosClient.get.mockResolvedValue({ status: 204, data: {} });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toThrowWithMessage(
        KeyStoreError,
        'Failed to retrieve key: Vault returned a 204 response',
      );
    });

    test('Error messages in 40X/50X responses should be included in error', async () => {
      const errorMessages: ReadonlyArray<any> = ['foo', 'bar'];
      mockAxiosClient.get.mockResolvedValue({ status: 204, data: { errors: errorMessages } });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toThrowWithMessage(
        KeyStoreError,
        `Failed to retrieve key: Vault returned a 204 response (${errorMessages.join(', ')})`,
      );
    });

    function makeVaultGETResponse(data: any, status: number): any {
      return {
        data: { data: { data } },
        status,
      };
    }
  });

  describe('close', () => {
    test('Close method should do nothing', async () => {
      mockAxiosCreate.mockReturnValue({ interceptors: { response: { use: jest.fn() } } } as any);
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.close();
    });
  });
});
