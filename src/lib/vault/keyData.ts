interface BaseKeyDataEncoded {
  readonly privateKey: string;
}

interface IdentityKeyDataEncoded extends BaseKeyDataEncoded {}

export interface SessionKeyDataEncoded extends BaseKeyDataEncoded {
  readonly nodeId: string;
  readonly peerId?: string;
}

export interface UnboundSessionKeyDataEncoded extends BaseKeyDataEncoded {
  readonly keyId: string;
}

export type KeyDataEncoded =
  | IdentityKeyDataEncoded
  | SessionKeyDataEncoded
  | UnboundSessionKeyDataEncoded;

interface BaseKeyDataDecoded {
  readonly privateKey: Buffer;
}

interface IdentityKeyDataDecoded extends BaseKeyDataDecoded {}

export interface SessionKeyDataDecoded extends BaseKeyDataDecoded {
  readonly peerId: string;
  readonly nodeId: string;
}

export interface UnboundSessionKeyDataDecoded extends BaseKeyDataDecoded {
  readonly keyId: string;
}

export type KeyDataDecoded =
  | IdentityKeyDataDecoded
  | SessionKeyDataDecoded
  | UnboundSessionKeyDataDecoded;
