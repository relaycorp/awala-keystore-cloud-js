declare module 'fast-crc32c' {
  export function calculate(plaintext: string | Buffer): number;
}
