import { deleteModelWithClass } from '@typegoose/typegoose';
import { Connection, ConnectOptions, createConnection } from 'mongoose';

import { GcpIdentityKey } from '../lib/gcp/models/GcpIdentityKey';
import { GcpSessionKey } from '../lib/gcp/models/GcpSessionKey';

const MODEL_CLASSES: readonly (new () => any)[] = [GcpIdentityKey, GcpSessionKey];

export function setUpTestDBConnection(): () => Connection {
  let connection: Connection;

  const connectionOptions: ConnectOptions = { bufferCommands: false };
  const connect = () =>
    createConnection((global as any).__MONGO_URI__, connectionOptions).asPromise();

  beforeAll(async () => {
    connection = await connect();
  });

  beforeEach(async () => {
    if (connection.readyState === 0) {
      connection = await connect();
    }
  });

  afterEach(async () => {
    if (connection.readyState === 0) {
      // The test closed the connection, so we shouldn't just reconnect, but also purge TypeGoose'
      // model cache because every item there is bound to the old connection.
      MODEL_CLASSES.forEach(deleteModelWithClass);
      connection = await connect();
    }

    await Promise.all(Object.values(connection.collections).map((c) => c.deleteMany({})));
  });

  afterAll(async () => {
    await connection.close(true);
  });

  return () => connection;
}
