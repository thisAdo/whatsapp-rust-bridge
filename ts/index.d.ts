export type BinaryNode = {
  tag: string;
  attrs: { [key: string]: string };
  content?: BinaryNode[] | string | Uint8Array;
};

export interface ILogger {
  level: string;
  trace(obj: object, msg?: string): void;
  debug(obj: object, msg?: string): void;
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
  error(obj: object, msg?: string): void;
}

export interface SignalStorage {
  loadSession(address: string): Promise<SessionRecord | Uint8Array | object | null | undefined>;
  storeSession(address: string, record: SessionRecord): Promise<void> | void;
  storeSessionRaw?(address: string, data: Uint8Array): Promise<void> | void;
  getOurIdentity(): Promise<KeyPair> | KeyPair;
  getOurRegistrationId(): Promise<number> | number;
  isTrustedIdentity(identifier: string, identityKey: Uint8Array, direction?: number): Promise<boolean> | boolean;
  loadPreKey(id: number): Promise<KeyPair | null | undefined> | KeyPair | null | undefined;
  removePreKey(id: number): Promise<void> | void;
  loadSignedPreKey(id: number): Promise<SignedPreKey | KeyPair | null | undefined> | SignedPreKey | KeyPair | null | undefined;
  loadSenderKey?(keyId: string): Promise<Uint8Array | null | undefined> | Uint8Array | null | undefined;
  storeSenderKey?(keyId: string, record: Uint8Array): Promise<void> | void;
}

export interface KeyPair {
  pubKey: Uint8Array;
  privKey: Uint8Array;
}

export interface EnabledFeatures {
  audio: boolean;
  image: boolean;
  sticker: boolean;
}

export interface HkdfInfo {
  salt?: Uint8Array | null | undefined;
  info?: string | undefined;
}

export interface PreKey {
  keyId: number;
  keyPair: KeyPair;
}

export interface PreKeyPublicKey {
  keyId: number;
  publicKey: Uint8Array;
}

export interface SignedPreKey {
  keyId: number;
  keyPair: KeyPair;
  signature: Uint8Array;
}

export interface SignedPreKeyPublicKey {
  keyId: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface PreKeyBundleInput {
  registrationId: number;
  identityKey: Uint8Array;
  preKey?: PreKeyPublicKey | undefined;
  signedPreKey: SignedPreKeyPublicKey;
}

export class InternalBinaryNode {
  constructor(node: BinaryNode);
  readonly tag: string;
  attrs: { [key: string]: string };
  content?: BinaryNode[] | string | Uint8Array;
  toJSON(): BinaryNode;
}

export class ExpandedAppStateKeys {
  readonly indexKey: Uint8Array;
  readonly valueEncryptionKey: Uint8Array;
  readonly valueMacKey: Uint8Array;
  readonly snapshotMacKey: Uint8Array;
  readonly patchMacKey: Uint8Array;
}

export class LTHashAntiTampering {
  subtractThenAdd(base: Uint8Array, subtract: Uint8Array[], add: Uint8Array[]): Uint8Array;
}

export class LTHashState {
  version: bigint;
  hash: Uint8Array;
  getValueMac(indexMacBase64: string): Uint8Array | undefined;
  setValueMac(indexMacBase64: string, valueMac: Uint8Array): void;
  deleteValueMac(indexMacBase64: string): boolean;
  hasValueMac(indexMacBase64: string): boolean;
  clone(): LTHashState;
}

export class ProtocolAddress {
  constructor(id: string, deviceId: number);
  static from(encodedAddress: string): ProtocolAddress;
  id: string;
  deviceId: number;
  toString(): string;
  is(other: ProtocolAddress): boolean;
}

export class SenderKeyName {
  constructor(groupId: string, sender: ProtocolAddress);
  getGroupId(): string;
  getSender(): ProtocolAddress;
  serialize(): string;
  toString(): string;
  equals(other: SenderKeyName | null): boolean;
  hashCode(): number;
}

export class SenderKeyRecord {
  constructor(serialized?: Uint8Array);
  static deserialize(data: Uint8Array): SenderKeyRecord;
  isEmpty(): boolean;
  serialize(): Uint8Array;
}

export class SenderKeyDistributionMessage {
  constructor(
    id?: number | null,
    iteration?: number | null,
    chainKey?: Uint8Array | null,
    signatureKey?: Uint8Array | null,
    serialized?: Uint8Array | null,
  );
  static deserialize(serialized: Uint8Array): SenderKeyDistributionMessage;
  serialize(): Uint8Array;
  getType(): number;
  getIteration(): number;
  getChainKey(): Uint8Array;
  getSignatureKey(): Uint8Array;
  getId(): number;
}

export class GroupSessionBuilder {
  constructor(storage: SignalStorage);
  process(senderKeyName: SenderKeyName, senderKeyDistributionMessage: SenderKeyDistributionMessage): Promise<void>;
  create(senderKeyName: SenderKeyName): Promise<SenderKeyDistributionMessage>;
}

export class GroupCipher {
  constructor(storage: SignalStorage, groupId: string, sender: ProtocolAddress);
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

export class SessionRecord {
  constructor(bytes?: Uint8Array);
  static deserialize(value: unknown): SessionRecord;
  serialize(): Uint8Array;
  haveOpenSession(): boolean;
}

export class SessionBuilder {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  initOutgoing(bundleInput: PreKeyBundleInput): Promise<void>;
  processPreKeyBundle(bundleInput: PreKeyBundleInput): Promise<void>;
}

export class SessionCipher {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  decryptPreKeyWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  decryptWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  encrypt(plaintext: Uint8Array): Promise<{ type: number; body: Uint8Array }>;
  hasOpenSession(): Promise<boolean>;
}

export class NoiseSession {
  constructor(publicKey: Uint8Array, noiseHeader: Uint8Array, routingInfo?: Uint8Array | null);
  readonly isFinished: boolean;
  readonly bufferedBytes: number;
  authenticate(data: Uint8Array): void;
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
  mixIntoKey(data: Uint8Array): void;
  finishInit(): void;
  encodeFrameRaw(data: Uint8Array): Uint8Array;
  encodeFrame(node: BinaryNode | InternalBinaryNode): Uint8Array;
  decodeFrame(data: Uint8Array): Array<InternalBinaryNode | Uint8Array>;
  clearBuffer(): void;
  getHash(): Uint8Array;
  processHandshakeInit(
    serverEphemeral: Uint8Array,
    serverStaticEncrypted: Uint8Array,
    serverPayloadEncrypted: Uint8Array,
    privateKey: Uint8Array,
  ): Uint8Array;
  processHandshakeFinish(
    noisePublicKey: Uint8Array,
    noisePrivateKey: Uint8Array,
    serverEphemeral: Uint8Array,
  ): Uint8Array;
}

export function encodeNode(nodeVal: BinaryNode | InternalBinaryNode): Uint8Array;
export function decodeNode(data: Uint8Array): InternalBinaryNode;
export function generateKeyPair(): KeyPair;
export function generateIdentityKeyPair(): KeyPair;
export function generateRegistrationId(): number;
export function calculateAgreement(publicKeyBytes: Uint8Array, privateKeyBytes: Uint8Array): Uint8Array;
export function calculateSignature(privateKeyBytes: Uint8Array, message: Uint8Array): Uint8Array;
export function verifySignature(publicKeyBytes: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
export function getPublicFromPrivateKey(privateKeyBytes: Uint8Array): Uint8Array;
export function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey;
export function generatePreKey(keyId: number): PreKey;
export function _serializeIdentityKeyPair(keyPair: KeyPair): Uint8Array;
export function md5(buffer: Uint8Array): Uint8Array;
export function hkdf(buffer: Uint8Array, expandedLength: number, info?: HkdfInfo): Uint8Array;
export function expandAppStateKeys(keyData: Uint8Array): ExpandedAppStateKeys;
export function generateContentMac(operation: number, data: Uint8Array, keyId: Uint8Array, key: Uint8Array): Uint8Array;
export function generateSnapshotMac(ltHash: Uint8Array, version: bigint, name: string, key: Uint8Array): Uint8Array;
export function generatePatchMac(
  snapshotMac: Uint8Array,
  valueMacs: Uint8Array[],
  version: bigint,
  name: string,
  key: Uint8Array,
): Uint8Array;
export function generateIndexMac(indexBytes: Uint8Array, key: Uint8Array): Uint8Array;
export function getEnabledFeatures(): EnabledFeatures;
export function getWAConnHeader(): Uint8Array;
export function setLogger(logger: ILogger): void;
export function updateLogger(logger: ILogger): void;
export function hasLogger(): boolean;
export function logMessage(level: string, message: string): void;
export function addStickerMetadata(...args: unknown[]): never;
export function getStickerMetadata(...args: unknown[]): never;
export function extractImageThumb(...args: unknown[]): never;
export function generateProfilePicture(...args: unknown[]): never;
export function getImageDimensions(...args: unknown[]): never;
export function convertToWebP(...args: unknown[]): never;
export function processImage(...args: unknown[]): never;
export function generateAudioWaveform(...args: unknown[]): never;
export function getAudioDuration(...args: unknown[]): Promise<never>;