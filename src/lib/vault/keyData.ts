interface BaseKeyDataEncoded {
  readonly privateKey: string;
}

interface IdentityKeyDataEncoded extends BaseKeyDataEncoded {}

export interface SessionKeyDataEncoded extends BaseKeyDataEncoded {
  readonly nodeId: string;
  readonly peerId?: string;
}

export type KeyDataEncoded = IdentityKeyDataEncoded | SessionKeyDataEncoded;

interface BaseKeyDataDecoded {
  readonly privateKey: Buffer;
}

interface IdentityKeyDataDecoded extends BaseKeyDataDecoded {}

export interface SessionKeyDataDecoded extends BaseKeyDataDecoded {
  readonly peerId: string;
  readonly nodeId: string;
}

interface InitialSessionKeyDataDecoded extends BaseKeyDataDecoded {}

export type KeyDataDecoded =
  | IdentityKeyDataDecoded
  | SessionKeyDataDecoded
  | InitialSessionKeyDataDecoded;
