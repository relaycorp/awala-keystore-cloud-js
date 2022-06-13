import { base64Decode, base64Encode } from './base64';
import { bufferToArrayBuffer } from './buffer';

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

  expect(base64Decode(valueEncoded)).toEqual(expectedOutput);
});
