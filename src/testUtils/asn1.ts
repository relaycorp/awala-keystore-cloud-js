export function derPublicKeyToPem(derBuffer: Buffer): string {
  const lines = derBuffer.toString('base64').match(/.{1,64}/g)!;
  return [`-----BEGIN PUBLIC KEY-----`, ...lines, `-----END PUBLIC KEY-----`].join('\n');
}
