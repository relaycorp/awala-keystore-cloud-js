import { expectBuffersToEqual } from '../../testUtils/vault_test_utils';
import { bufferToArrayBuffer } from '../utils/buffer';
import { base64Decode, base64Encode } from './base64';

const valueDecoded = 'hi';
const valueEncoded = 'aGk=';

describe('base64Encode', () => {
  test('Buffer should be base64 encoded', () => {
    const input = Buffer.from(valueDecoded);

    expect(base64Encode(input)).toEqual(valueEncoded);
  });

  test('ArrayBuffer should be base64 encoded', () => {
    const input = bufferToArrayBuffer(Buffer.from(valueDecoded));

    expect(base64Encode(input)).toEqual(valueEncoded);
  });
});

test('base64Decode should decode input', () => {
  const expectedOutput = Buffer.from(valueDecoded);

  expectBuffersToEqual(base64Decode(valueEncoded), expectedOutput);
});
