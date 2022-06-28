interface BaseKeyDataEncoded {
  readonly privateKey: string;
}

interface IdentityKeyDataEncoded extends BaseKeyDataEncoded {}

export interface SessionKeyDataEncoded extends BaseKeyDataEncoded {
  readonly privateAddress: string;
  readonly peerPrivateAddress?: string;
}

export type KeyDataEncoded = IdentityKeyDataEncoded | SessionKeyDataEncoded;

interface BaseKeyDataDecoded {
  readonly privateKey: Buffer;
}

interface IdentityKeyDataDecoded extends BaseKeyDataDecoded {}

export interface SessionKeyDataDecoded extends BaseKeyDataDecoded {
  readonly peerPrivateAddress: string;
  readonly privateAddress: string;
}

export type KeyDataDecoded = IdentityKeyDataDecoded | SessionKeyDataDecoded;
