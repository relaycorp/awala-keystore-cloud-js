import { deleteModelWithClass } from '@typegoose/typegoose';
import { Connection, ConnectOptions, createConnection } from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

import { GcpIdentityKey } from '../lib/gcp/models/GcpIdentityKey';
import { GcpSessionKey } from '../lib/gcp/models/GcpSessionKey';

const MODEL_CLASSES: readonly (new () => any)[] = [GcpIdentityKey, GcpSessionKey];

export function setUpTestDBConnection(): () => Connection {
  let connectionURI: string;
  let connection: Connection;
  const mongoServer = new MongoMemoryServer();
  beforeAll(async () => {
    await mongoServer.start();
    connectionURI = mongoServer.getUri();
    connection = await connect();
  });

  const connectionOptions: ConnectOptions = { bufferCommands: false };
  const connect = () => createConnection(connectionURI, connectionOptions).asPromise();

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
    await mongoServer.stop();
  });

  return () => connection;
}
