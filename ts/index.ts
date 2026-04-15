import { createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { NOISE_MODE, NOISE_WA_HEADER } from 'baileys/lib/Defaults/index.js';
import { GroupSessionBuilder as NativeGroupSessionBuilder } from 'baileys/lib/Signal/Group/group-session-builder.js';
import { GroupCipher as NativeGroupCipher } from 'baileys/lib/Signal/Group/group_cipher.js';
import { SenderKeyDistributionMessage as NativeSenderKeyDistributionMessage } from 'baileys/lib/Signal/Group/sender-key-distribution-message.js';
import { SenderKeyName as NativeSenderKeyName } from 'baileys/lib/Signal/Group/sender-key-name.js';
import { SenderKeyRecord as NativeSenderKeyRecord } from 'baileys/lib/Signal/Group/sender-key-record.js';
import { BufferJSON } from 'baileys/lib/Utils/generics.js';
import {
  Curve as NoiseCurve,
  aesDecryptGCM,
  aesEncryptGCM,
} from 'baileys/lib/Utils/crypto.js';
import * as binaryConstants from 'baileys/lib/WABinary/constants.js';
import { decodeDecompressedBinaryNode } from 'baileys/lib/WABinary/decode.js';
import { encodeBinaryNode } from 'baileys/lib/WABinary/encode.js';
import libSignalCurve from 'libsignal/src/curve.js';
import libSignalKeyHelper from 'libsignal/src/keyhelper.js';
import LibSignalProtocolAddress from 'libsignal/src/protocol_address.js';
import LibSignalSessionBuilder from 'libsignal/src/session_builder.js';
import LibSignalSessionCipher from 'libsignal/src/session_cipher.js';
import LibSignalSessionRecord from 'libsignal/src/session_record.js';

const SERVER_ONLY_ATTRS = Symbol('serverOnlyAttrs');
const OPTIONAL_FEATURES = Object.freeze({
  audio: false,
  image: false,
  sticker: false,
});

const ED25519_FIELD = (1n << 255n) - 19n;
const ED25519_BASE_X =
  15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const ED25519_BASE_Y =
  46316835694926478169428394003475163141307993866256225615783033603165251855960n;

function ed25519Mod(value) {
  const result = value % ED25519_FIELD;
  return result >= 0n ? result : result + ED25519_FIELD;
}

function ed25519Pow(base, exponent) {
  let result = 1n;
  let factor = ed25519Mod(base);
  let power = exponent;

  while (power > 0n) {
    if (power & 1n) {
      result = ed25519Mod(result * factor);
    }

    factor = ed25519Mod(factor * factor);
    power >>= 1n;
  }

  return result;
}

function ed25519Inv(value) {
  return ed25519Pow(value, ED25519_FIELD - 2n);
}

const ED25519_D = ed25519Mod(-121665n * ed25519Inv(121666n));
const ED25519_IDENTITY = {
  X: 0n,
  Y: 1n,
  Z: 1n,
  T: 0n,
};
const ED25519_BASE_POINT = {
  X: ED25519_BASE_X,
  Y: ED25519_BASE_Y,
  Z: 1n,
  T: ed25519Mod(ED25519_BASE_X * ED25519_BASE_Y),
};

function ed25519Add(left, right) {
  const a = ed25519Mod((left.Y - left.X) * (right.Y - right.X));
  const b = ed25519Mod((left.Y + left.X) * (right.Y + right.X));
  const c = ed25519Mod(2n * ED25519_D * left.T * right.T);
  const d = ed25519Mod(2n * left.Z * right.Z);
  const e = ed25519Mod(b - a);
  const f = ed25519Mod(d - c);
  const g = ed25519Mod(d + c);
  const h = ed25519Mod(b + a);

  return {
    X: ed25519Mod(e * f),
    Y: ed25519Mod(g * h),
    Z: ed25519Mod(f * g),
    T: ed25519Mod(e * h),
  };
}

function ed25519Double(point) {
  const a = ed25519Mod(point.X * point.X);
  const b = ed25519Mod(point.Y * point.Y);
  const c = ed25519Mod(2n * point.Z * point.Z);
  const d = ed25519Mod(-a);
  const e = ed25519Mod((point.X + point.Y) * (point.X + point.Y) - a - b);
  const g = ed25519Mod(d + b);
  const f = ed25519Mod(g - c);
  const h = ed25519Mod(d - b);

  return {
    X: ed25519Mod(e * f),
    Y: ed25519Mod(g * h),
    Z: ed25519Mod(f * g),
    T: ed25519Mod(e * h),
  };
}

function readBigIntLE(bytes) {
  let value = 0n;

  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) + BigInt(bytes[index]);
  }

  return value;
}

function ed25519MultiplyBase(privateKey) {
  const scalarBytes = Uint8Array.from(privateKey);
  scalarBytes[0] &= 248;
  scalarBytes[31] &= 127;
  scalarBytes[31] |= 64;

  let scalar = readBigIntLE(scalarBytes);
  let result = ED25519_IDENTITY;
  let addend = ED25519_BASE_POINT;

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = ed25519Add(result, addend);
    }

    addend = ed25519Double(addend);
    scalar >>= 1n;
  }

  return result;
}

function encodeEd25519Point(point) {
  const inverseZ = ed25519Inv(point.Z);
  const x = ed25519Mod(point.X * inverseZ);
  const y = ed25519Mod(point.Y * inverseZ);
  const encoded = new Uint8Array(32);
  let remaining = y;

  for (let index = 0; index < encoded.length; index += 1) {
    encoded[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }

  encoded[31] |= Number((x & 1n) << 7n);
  return encoded;
}

let currentLogger = null;

function copyUint8Array(value) {
  return Uint8Array.from(value);
}

function isBufferJson(value) {
  return Boolean(value && typeof value === 'object' && value.type === 'Buffer');
}

function coerceBytes(value, fieldName = 'value') {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }

  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }

  if (value instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(value));
  }

  if (Array.isArray(value)) {
    return Buffer.from(value);
  }

  if (isBufferJson(value)) {
    if (Array.isArray(value.data)) {
      return Buffer.from(value.data);
    }

    const revived = BufferJSON.reviver('', value);
    if (Buffer.isBuffer(revived)) {
      return Buffer.from(revived);
    }
  }

  throw new TypeError(`${fieldName} must be bytes`);
}

function coerceOptionalBytes(value) {
  if (value === null || typeof value === 'undefined') {
    return Buffer.alloc(0);
  }

  return coerceBytes(value);
}

function toUint8Array(value) {
  return copyUint8Array(coerceBytes(value));
}

function encodeJsonBytes(value) {
  return Buffer.from(JSON.stringify(value, BufferJSON.replacer), 'utf8');
}

function decodeJsonBytes(bytes) {
  return JSON.parse(Buffer.from(bytes).toString('utf8'), BufferJSON.reviver);
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest();
}

function hkdfBytes(buffer, expandedLength, info = {}) {
  return Buffer.from(
    hkdfSync(
      'sha256',
      coerceBytes(buffer),
      coerceOptionalBytes(info.salt),
      Buffer.from(info.info ?? '', 'utf8'),
      expandedLength,
    ),
  );
}

function u64be(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function generateIv(counter) {
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(counter >>> 0, 8);
  return iv;
}

function defineServerOnlyAttrs(target, keys) {
  Object.defineProperty(target, SERVER_ONLY_ATTRS, {
    value: keys,
    enumerable: false,
    configurable: true,
    writable: true,
  });
  return target;
}

function getServerOnlyAttrs(target) {
  if (target instanceof InternalBinaryNode) {
    return target.getServerOnlyAttrs();
  }

  return target?.[SERVER_ONLY_ATTRS] instanceof Set ? target[SERVER_ONLY_ATTRS] : new Set();
}

function isServerOnlyJid(value) {
  return typeof value === 'string' && !value.includes('@') && value.includes('.');
}

function normalizeUserNode(node) {
  if (node instanceof InternalBinaryNode) {
    return node.toEncodingNode();
  }

  if (!node || typeof node !== 'object') {
    throw new TypeError('Invalid binary node');
  }

  const attrs = {};
  for (const [key, value] of Object.entries(node.attrs ?? {})) {
    attrs[key] = value;
  }

  const normalized = {
    tag: String(node.tag),
    attrs,
  };

  if (typeof node.content !== 'undefined') {
    normalized.content = normalizeUserContent(node.content);
  }

  const serverOnlyAttrs = getServerOnlyAttrs(node);
  if (serverOnlyAttrs.size) {
    defineServerOnlyAttrs(normalized, new Set(serverOnlyAttrs));
  }

  return normalized;
}

function normalizeUserContent(content) {
  if (Array.isArray(content)) {
    return content.map(normalizeUserNode);
  }

  if (Buffer.isBuffer(content) || content instanceof Uint8Array || content instanceof ArrayBuffer) {
    return toUint8Array(content);
  }

  return content;
}

function normalizeDecodedNode(node) {
  const attrs = {};
  const serverOnlyAttrs = new Set();

  for (const [key, value] of Object.entries(node.attrs ?? {})) {
    if (typeof value === 'string' && value.startsWith('@') && value.indexOf('@', 1) === -1) {
      attrs[key] = value.slice(1);
      serverOnlyAttrs.add(key);
      continue;
    }

    attrs[key] = value;
  }

  const normalized = {
    tag: node.tag,
    attrs,
  };

  if (Array.isArray(node.content)) {
    normalized.content = node.content.map(normalizeDecodedNode);
  } else if (Buffer.isBuffer(node.content) || node.content instanceof Uint8Array) {
    normalized.content = toUint8Array(node.content);
  } else if (typeof node.content !== 'undefined') {
    normalized.content = node.content;
  }

  if (serverOnlyAttrs.size) {
    defineServerOnlyAttrs(normalized, serverOnlyAttrs);
  }

  return normalized;
}

function normalizeEncodingNode(node) {
  const source = normalizeUserNode(node);
  const attrs = {};

  for (const [key, value] of Object.entries(source.attrs ?? {})) {
    if (value === null || typeof value === 'undefined') {
      continue;
    }

    const text = typeof value === 'string' ? value : String(value);
    if (text.trim() === '') {
      continue;
    }

    attrs[key] = text;
  }

  const normalized = {
    tag: String(source.tag),
    attrs,
  };

  if (typeof source.content !== 'undefined') {
    normalized.content = normalizeEncodingContent(source.content);
  }

  return normalized;
}

function normalizeEncodingContent(content) {
  if (Array.isArray(content)) {
    return content
      .filter(Boolean)
      .map(item => normalizeEncodingNode(item));
  }

  if (Buffer.isBuffer(content) || content instanceof Uint8Array || content instanceof ArrayBuffer) {
    return toUint8Array(content);
  }

  return content;
}

function looksLegacySessionObject(value) {
  return Boolean(
    value &&
      typeof value === 'object' &&
      ((value._sessions && typeof value._sessions === 'object') ||
        (value.currentRatchet && value.indexInfo)),
  );
}

function wrapLegacySessionObject(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }

  if (value._sessions && typeof value._sessions === 'object') {
    return value;
  }

  if (!value.currentRatchet || !value.indexInfo) {
    return null;
  }

  const baseKey =
    typeof value.indexInfo.baseKey === 'string'
      ? value.indexInfo.baseKey
      : Buffer.from(randomBytes(32)).toString('base64');

  return {
    _sessions: {
      [baseKey]: value,
    },
    version: value.version ?? 'v1',
  };
}

function encodeSessionRecord(record) {
  return copyUint8Array(encodeJsonBytes(record.serialize()));
}

function decodeSessionBytes(bytes) {
  if (!bytes.length) {
    return new LibSignalSessionRecord();
  }

  try {
    const parsed = decodeJsonBytes(bytes);
    if (looksLegacySessionObject(parsed)) {
      return LibSignalSessionRecord.deserialize(wrapLegacySessionObject(parsed));
    }
  } catch {
    return new LibSignalSessionRecord();
  }

  return new LibSignalSessionRecord();
}

function encodeSenderKeyRecord(record) {
  return copyUint8Array(encodeJsonBytes(record.serialize()));
}

function decodeSenderKeyRecord(bytes) {
  if (!bytes.length) {
    return new NativeSenderKeyRecord();
  }

  return NativeSenderKeyRecord.deserialize(bytes);
}

function normalizeKeyPair(value, context = 'KeyPair') {
  if (!value || typeof value !== 'object') {
    throw new TypeError(`Invalid argument for ${context}`);
  }

  return {
    pubKey: toUint8Array(value.pubKey),
    privKey: toUint8Array(value.privKey),
  };
}

function normalizeSignedPreKey(value) {
  return {
    keyId: Number(value.keyId),
    keyPair: normalizeKeyPair(value.keyPair, 'SignedPreKey.keyPair'),
    signature: toUint8Array(value.signature),
  };
}

function normalizePreKey(value) {
  return {
    keyId: Number(value.keyId),
    keyPair: normalizeKeyPair(value.keyPair, 'PreKey.keyPair'),
  };
}

function normalizeBundleInput(value) {
  return {
    registrationId: Number(value.registrationId),
    identityKey: coerceBytes(value.identityKey, 'identityKey'),
    signedPreKey: {
      keyId: Number(value.signedPreKey.keyId),
      publicKey: coerceBytes(value.signedPreKey.publicKey, 'signedPreKey.publicKey'),
      signature: coerceBytes(value.signedPreKey.signature, 'signedPreKey.signature'),
    },
    ...(value.preKey
      ? {
          preKey: {
            keyId: Number(value.preKey.keyId),
            publicKey: coerceBytes(value.preKey.publicKey, 'preKey.publicKey'),
          },
        }
      : {}),
  };
}

function remapSignalError(error, address) {
  if (error?.name === 'UntrustedIdentityKeyError') {
    return new Error(`untrusted identity for address ${address.toString()}`);
  }

  if (error instanceof Error) {
    return error;
  }

  return new Error(String(error));
}

function parseLoggerMethod(level) {
  switch (String(level).toLowerCase()) {
    case 'trace':
      return 'trace';
    case 'debug':
      return 'debug';
    case 'warn':
    case 'warning':
      return 'warn';
    case 'error':
      return 'error';
    default:
      return 'info';
  }
}

function hmac(variant, key, data) {
  return createHmac(variant, key).update(data).digest();
}

class SignalStorageAdapter {
  #storage;

  constructor(storage) {
    this.#storage = storage;
  }

  async loadSession(address) {
    const value = await this.#storage.loadSession(address);

    if (!value) {
      return undefined;
    }

    if (value instanceof LibSignalSessionRecord) {
      return value;
    }

    if (value instanceof SessionRecord) {
      return decodeSessionBytes(coerceBytes(value.serialize()));
    }

    if (looksLegacySessionObject(value)) {
      return LibSignalSessionRecord.deserialize(wrapLegacySessionObject(value));
    }

    try {
      return decodeSessionBytes(coerceBytes(value, 'session'));
    } catch {
      return new LibSignalSessionRecord();
    }
  }

  async storeSession(address, record) {
    const serialized = encodeSessionRecord(record);

    if (typeof this.#storage.storeSessionRaw === 'function') {
      await this.#storage.storeSessionRaw(address, serialized);
      return;
    }

    if (typeof this.#storage.storeSession === 'function') {
      await this.#storage.storeSession(address, SessionRecord.fromNative(record));
      return;
    }

    throw new TypeError('storeSession is required');
  }

  async getOurIdentity() {
    const value = await this.#storage.getOurIdentity();
    const pair = normalizeKeyPair(value, 'identityKeyPair');

    return {
      pubKey: Buffer.from(pair.pubKey),
      privKey: Buffer.from(pair.privKey),
    };
  }

  async getOurRegistrationId() {
    return this.#storage.getOurRegistrationId();
  }

  async isTrustedIdentity(identifier, identityKey, direction) {
    return this.#storage.isTrustedIdentity(identifier, copyUint8Array(identityKey), direction);
  }

  async loadPreKey(id) {
    const value = await this.#storage.loadPreKey(Number(id));
    if (!value) {
      return undefined;
    }

    const pair = value.keyPair ? normalizeKeyPair(value.keyPair, 'preKey') : normalizeKeyPair(value, 'preKey');
    return {
      pubKey: Buffer.from(pair.pubKey),
      privKey: Buffer.from(pair.privKey),
    };
  }

  async removePreKey(id) {
    await this.#storage.removePreKey(Number(id));
  }

  async loadSignedPreKey(id) {
    const value = await this.#storage.loadSignedPreKey(Number(id));
    if (!value) {
      return undefined;
    }

    const pair = value.keyPair
      ? normalizeKeyPair(value.keyPair, 'signedPreKey')
      : normalizeKeyPair(value, 'signedPreKey');

    return {
      pubKey: Buffer.from(pair.pubKey),
      privKey: Buffer.from(pair.privKey),
    };
  }
}

class GroupStorageAdapter {
  #storage;

  constructor(storage) {
    this.#storage = storage;
  }

  async loadSenderKey(senderKeyName) {
    const value = await this.#storage.loadSenderKey(senderKeyName.toString());

    if (!value) {
      return new NativeSenderKeyRecord();
    }

    if (value instanceof NativeSenderKeyRecord) {
      return value;
    }

    if (value instanceof SenderKeyRecord) {
      return value.toNative();
    }

    try {
      return decodeSenderKeyRecord(coerceBytes(value, 'senderKey'));
    } catch {
      return new NativeSenderKeyRecord();
    }
  }

  async storeSenderKey(senderKeyName, record) {
    await this.#storage.storeSenderKey(senderKeyName.toString(), encodeSenderKeyRecord(record));
  }
}

export class InternalBinaryNode {
  #tag;
  #attrs;
  #content;
  #serverOnlyAttrs;

  constructor(node) {
    this.#tag = node.tag;
    this.#attrs = node.attrs ?? {};
    this.#content = node.content;
    this.#serverOnlyAttrs = new Set(getServerOnlyAttrs(node));
  }

  get tag() {
    return this.#tag;
  }

  get attrs() {
    return this.#attrs;
  }

  set attrs(value) {
    this.#attrs = value && typeof value === 'object' ? { ...value } : {};
    this.#serverOnlyAttrs = new Set();
  }

  get content() {
    return this.#content;
  }

  set content(value) {
    this.#content = normalizeUserContent(value);
  }

  getServerOnlyAttrs() {
    return this.#serverOnlyAttrs;
  }

  toEncodingNode() {
    const output = this.toJSON();
    if (this.#serverOnlyAttrs.size) {
      defineServerOnlyAttrs(output, new Set(this.#serverOnlyAttrs));
    }
    return output;
  }

  toJSON() {
    const output = {
      tag: this.#tag,
      attrs: this.#attrs,
    };

    if (typeof this.#content !== 'undefined') {
      output.content = this.#content;
    }

    return output;
  }
}

export class ExpandedAppStateKeys {
  #indexKey;
  #valueEncryptionKey;
  #valueMacKey;
  #snapshotMacKey;
  #patchMacKey;

  constructor(keys) {
    this.#indexKey = copyUint8Array(keys.indexKey);
    this.#valueEncryptionKey = copyUint8Array(keys.valueEncryptionKey);
    this.#valueMacKey = copyUint8Array(keys.valueMacKey);
    this.#snapshotMacKey = copyUint8Array(keys.snapshotMacKey);
    this.#patchMacKey = copyUint8Array(keys.patchMacKey);
  }

  get indexKey() {
    return copyUint8Array(this.#indexKey);
  }

  get valueEncryptionKey() {
    return copyUint8Array(this.#valueEncryptionKey);
  }

  get valueMacKey() {
    return copyUint8Array(this.#valueMacKey);
  }

  get snapshotMacKey() {
    return copyUint8Array(this.#snapshotMacKey);
  }

  get patchMacKey() {
    return copyUint8Array(this.#patchMacKey);
  }
}

export class LTHashAntiTampering {
  subtractThenAdd(base, subtract, add) {
    const current = toUint8Array(base);
    if (current.length !== 128) {
      throw new Error(`Base hash must be 128 bytes, got ${current.length}`);
    }

    let next = current.buffer.slice(current.byteOffset, current.byteOffset + current.byteLength);

    for (const item of subtract ?? []) {
      next = this.#apply(next, coerceBytes(item), (left, right) => left - right);
    }

    for (const item of add ?? []) {
      next = this.#apply(next, coerceBytes(item), (left, right) => left + right);
    }

    return new Uint8Array(next);
  }

  #apply(base, item, operation) {
    const derived = hkdfBytes(item, 128, { info: 'WhatsApp Patch Integrity' });
    const left = new DataView(base);
    const right = new DataView(derived.buffer, derived.byteOffset, derived.byteLength);
    const output = new ArrayBuffer(128);
    const view = new DataView(output);

    for (let offset = 0; offset < 128; offset += 2) {
      const value = operation(left.getUint16(offset, true), right.getUint16(offset, true));
      view.setUint16(offset, value & 0xffff, true);
    }

    return output;
  }
}

export class LTHashState {
  #version;
  #hash;
  #indexValueMap;

  constructor() {
    this.#version = 0n;
    this.#hash = new Uint8Array(128);
    this.#indexValueMap = new Map();
  }

  get version() {
    return this.#version;
  }

  set version(value) {
    this.#version = BigInt(value);
  }

  get hash() {
    return copyUint8Array(this.#hash);
  }

  set hash(value) {
    const next = toUint8Array(value);
    if (next.length !== 128) {
      throw new Error(`Hash must be 128 bytes, got ${next.length}`);
    }

    this.#hash = next;
  }

  getValueMac(indexMacBase64) {
    const value = this.#indexValueMap.get(indexMacBase64);
    return typeof value === 'undefined' ? undefined : copyUint8Array(value);
  }

  setValueMac(indexMacBase64, valueMac) {
    this.#indexValueMap.set(indexMacBase64, toUint8Array(valueMac));
  }

  deleteValueMac(indexMacBase64) {
    return this.#indexValueMap.delete(indexMacBase64);
  }

  hasValueMac(indexMacBase64) {
    return this.#indexValueMap.has(indexMacBase64);
  }

  clone() {
    const next = new LTHashState();
    next.version = this.#version;
    next.hash = this.#hash;

    for (const [key, value] of this.#indexValueMap.entries()) {
      next.setValueMac(key, value);
    }

    return next;
  }
}

export class ProtocolAddress {
  constructor(id, deviceId) {
    if (typeof id !== 'string') {
      throw new TypeError('id required for addr');
    }

    if (id.includes('.')) {
      throw new TypeError('encoded addr detected');
    }

    if (!Number.isInteger(deviceId)) {
      throw new TypeError('number required for deviceId');
    }

    this.id = id;
    this.deviceId = deviceId;
  }

  static from(encodedAddress) {
    if (typeof encodedAddress !== 'string' || !encodedAddress.match(/.*\.\d+/)) {
      throw new Error('Invalid address encoding');
    }

    const parts = encodedAddress.split('.');
    const deviceId = Number.parseInt(parts[1], 10);
    if (!Number.isInteger(deviceId)) {
      throw new Error('Invalid address encoding');
    }

    return new ProtocolAddress(parts[0], deviceId);
  }

  toString() {
    return `${this.id}.${this.deviceId}`;
  }

  is(other) {
    if (!(other instanceof ProtocolAddress)) {
      throw new TypeError('ProtocolAddress expected');
    }

    return other.id === this.id && other.deviceId === this.deviceId;
  }

  toNative() {
    return new LibSignalProtocolAddress(this.id, this.deviceId);
  }
}

function intValue(num) {
  const maxValue = 0x7fffffff;
  const minValue = -0x80000000;
  if (num > maxValue || num < minValue) {
    return num & 0xffffffff;
  }
  return num;
}

function hashCode(strKey) {
  let hash = 0;
  if (strKey !== null && strKey !== '') {
    for (let index = 0; index < strKey.length; index += 1) {
      hash = hash * 31 + strKey.charCodeAt(index);
      hash = intValue(hash);
    }
  }
  return hash;
}

export class SenderKeyName {
  constructor(groupId, sender) {
    this.groupId = groupId;
    this.sender = sender;
  }

  getGroupId() {
    return this.groupId;
  }

  getSender() {
    return this.sender;
  }

  serialize() {
    return `${this.groupId}::${this.sender.id}::${this.sender.deviceId}`;
  }

  toString() {
    return this.serialize();
  }

  equals(other) {
    if (!(other instanceof SenderKeyName)) {
      return false;
    }

    return this.groupId === other.groupId && this.sender.toString() === other.sender.toString();
  }

  hashCode() {
    return hashCode(this.groupId) ^ hashCode(this.sender.toString());
  }

  toNative() {
    return new NativeSenderKeyName(this.groupId, {
      id: this.sender.id,
      deviceId: this.sender.deviceId,
      toString: () => this.sender.toString(),
    });
  }
}

export class SenderKeyRecord {
  #native;

  constructor(serialized) {
    this.#native = serialized instanceof NativeSenderKeyRecord ? serialized : decodeSenderKeyRecord(serialized ? coerceBytes(serialized) : new Uint8Array());
  }

  static deserialize(data) {
    return new SenderKeyRecord(coerceBytes(data));
  }

  static fromNative(record) {
    return new SenderKeyRecord(record);
  }

  toNative() {
    return this.#native;
  }

  isEmpty() {
    return this.#native.isEmpty();
  }

  serialize() {
    return encodeSenderKeyRecord(this.#native);
  }
}

export class SenderKeyDistributionMessage {
  #native;

  constructor(id = null, iteration = null, chainKey = null, signatureKey = null, serialized = null) {
    this.#native = serialized
      ? new NativeSenderKeyDistributionMessage(null, null, null, null, coerceBytes(serialized))
      : new NativeSenderKeyDistributionMessage(
          id,
          iteration,
          chainKey ? coerceBytes(chainKey) : null,
          signatureKey ? coerceBytes(signatureKey) : null,
          null,
        );
  }

  static deserialize(serialized) {
    return new SenderKeyDistributionMessage(null, null, null, null, serialized);
  }

  static fromNative(message) {
    return new SenderKeyDistributionMessage(null, null, null, null, message.serialize());
  }

  toNative() {
    return this.#native;
  }

  serialize() {
    return copyUint8Array(this.#native.serialize());
  }

  getType() {
    return this.#native.getType();
  }

  getIteration() {
    return this.#native.getIteration();
  }

  getChainKey() {
    return copyUint8Array(this.#native.getChainKey());
  }

  getSignatureKey() {
    return copyUint8Array(this.#native.getSignatureKey());
  }

  getId() {
    return this.#native.getId();
  }
}

export class GroupSessionBuilder {
  #native;

  constructor(storage) {
    this.#native = new NativeGroupSessionBuilder(new GroupStorageAdapter(storage));
  }

  async process(senderKeyName, senderKeyDistributionMessage) {
    await this.#native.process(senderKeyName.toNative(), senderKeyDistributionMessage.toNative());
  }

  async create(senderKeyName) {
    const native = await this.#native.create(senderKeyName.toNative());
    return SenderKeyDistributionMessage.fromNative(native);
  }
}

export class GroupCipher {
  #native;

  constructor(storage, groupId, sender) {
    const senderKeyName = new SenderKeyName(groupId, sender);
    this.#native = new NativeGroupCipher(new GroupStorageAdapter(storage), senderKeyName.toNative());
  }

  async encrypt(plaintext) {
    return copyUint8Array(await this.#native.encrypt(coerceBytes(plaintext)));
  }

  async decrypt(ciphertext) {
    return copyUint8Array(await this.#native.decrypt(coerceBytes(ciphertext)));
  }
}

export class SessionRecord {
  #bytes;

  constructor(bytes = new Uint8Array()) {
    this.#bytes = copyUint8Array(bytes);
  }

  static deserialize(value) {
    if (value instanceof SessionRecord) {
      return new SessionRecord(value.serialize());
    }

    if (looksLegacySessionObject(value)) {
      return new SessionRecord();
    }

    if (value === null || typeof value === 'undefined' || typeof value === 'string' || typeof value === 'number') {
      throw new TypeError('Invalid session record input');
    }

    return new SessionRecord(coerceBytes(value));
  }

  static fromNative(record) {
    return new SessionRecord(encodeSessionRecord(record));
  }

  serialize() {
    return copyUint8Array(this.#bytes);
  }

  haveOpenSession() {
    return decodeSessionBytes(this.#bytes).haveOpenSession();
  }
}

export class SessionBuilder {
  #storage;
  #address;
  #native;

  constructor(storage, remoteAddress) {
    this.#storage = new SignalStorageAdapter(storage);
    this.#address = remoteAddress;
    this.#native = new LibSignalSessionBuilder(this.#storage, remoteAddress.toNative());
  }

  async initOutgoing(bundleInput) {
    const existing = await this.#storage.loadSession(this.#address.toString());
    if (existing?.haveOpenSession()) {
      return;
    }

    await this.processPreKeyBundle(bundleInput);
  }

  async processPreKeyBundle(bundleInput) {
    try {
      await this.#native.initOutgoing(normalizeBundleInput(bundleInput));
    } catch (error) {
      throw remapSignalError(error, this.#address);
    }
  }
}

export class SessionCipher {
  #address;
  #native;

  constructor(storage, remoteAddress) {
    this.#address = remoteAddress;
    this.#native = new LibSignalSessionCipher(new SignalStorageAdapter(storage), remoteAddress.toNative());
  }

  async decryptPreKeyWhisperMessage(ciphertext) {
    try {
      return copyUint8Array(await this.#native.decryptPreKeyWhisperMessage(coerceBytes(ciphertext)));
    } catch (error) {
      throw remapSignalError(error, this.#address);
    }
  }

  async decryptWhisperMessage(ciphertext) {
    try {
      return copyUint8Array(await this.#native.decryptWhisperMessage(coerceBytes(ciphertext)));
    } catch (error) {
      throw remapSignalError(error, this.#address);
    }
  }

  async encrypt(plaintext) {
    try {
      const result = await this.#native.encrypt(coerceBytes(plaintext));
      return {
        type: result.type === 1 ? 2 : result.type,
        body: copyUint8Array(result.body),
      };
    } catch (error) {
      throw remapSignalError(error, this.#address);
    }
  }

  async hasOpenSession() {
    try {
      return await this.#native.hasOpenSession();
    } catch (error) {
      throw remapSignalError(error, this.#address);
    }
  }
}

export class NoiseSession {
  #hash;
  #salt;
  #encKey;
  #decKey;
  #readCounter;
  #writeCounter;
  #isFinished;
  #introHeader;
  #sentIntro;
  #buffer;

  constructor(publicKey, noiseHeader, routingInfo = undefined) {
    const keyBytes = coerceBytes(publicKey, 'public_key');
    const headerBytes = coerceBytes(noiseHeader, 'noise_header');
    const mode = Buffer.from(NOISE_MODE);

    this.#hash = mode.length === 32 ? Buffer.from(mode) : sha256(mode);
    this.#salt = Buffer.from(this.#hash);
    this.#encKey = Buffer.from(this.#hash);
    this.#decKey = Buffer.from(this.#hash);
    this.#readCounter = 0;
    this.#writeCounter = 0;
    this.#isFinished = false;
    this.#sentIntro = false;
    this.#buffer = Buffer.alloc(0);
    this.#introHeader = this.#buildIntroHeader(headerBytes, routingInfo);

    this.authenticate(headerBytes);
    this.authenticate(keyBytes);
  }

  get isFinished() {
    return this.#isFinished;
  }

  get bufferedBytes() {
    return this.#buffer.length;
  }

  authenticate(data) {
    if (!this.#isFinished) {
      this.#hash = sha256(Buffer.concat([this.#hash, coerceBytes(data)]));
    }
  }

  encrypt(plaintext) {
    const payload = coerceBytes(plaintext);
    const key = this.#isFinished ? this.#encKey : this.#encKey;
    const counter = this.#isFinished ? this.#writeCounter : this.#writeCounter;
    const encrypted = this.#aesEncrypt(payload, key, generateIv(counter), this.#hash);
    this.#writeCounter += 1;
    this.authenticate(encrypted);
    return copyUint8Array(encrypted);
  }

  decrypt(ciphertext) {
    const payload = coerceBytes(ciphertext);
    const counter = this.#isFinished ? this.#readCounter : this.#writeCounter;
    const key = this.#isFinished ? this.#decKey : this.#decKey;
    const decrypted = this.#aesDecrypt(payload, key, generateIv(counter), this.#hash);

    if (this.#isFinished) {
      this.#readCounter += 1;
    } else {
      this.#writeCounter += 1;
    }

    this.authenticate(payload);
    return copyUint8Array(decrypted);
  }

  mixIntoKey(data) {
    const derived = hkdfBytes(data, 64, { salt: this.#salt, info: '' });
    this.#salt = Buffer.from(derived.subarray(0, 32));
    this.#encKey = Buffer.from(derived.subarray(32));
    this.#decKey = Buffer.from(derived.subarray(32));
    this.#readCounter = 0;
    this.#writeCounter = 0;
  }

  finishInit() {
    const derived = hkdfBytes(Buffer.alloc(0), 64, { salt: this.#salt, info: '' });
    this.#encKey = Buffer.from(derived.subarray(0, 32));
    this.#decKey = Buffer.from(derived.subarray(32));
    this.#hash = Buffer.alloc(0);
    this.#readCounter = 0;
    this.#writeCounter = 0;
    this.#isFinished = true;
  }

  encodeFrameRaw(data) {
    const payload = this.#isFinished ? this.encrypt(data) : toUint8Array(data);
    return this.#encodeFrameBytes(payload);
  }

  encodeFrame(node) {
    const payload = encodeNode(node);
    return this.#encodeFrameBytes(this.#isFinished ? this.encrypt(payload) : payload);
  }

  decodeFrame(newData) {
    this.#buffer = Buffer.concat([this.#buffer, coerceBytes(newData)]);
    const frames = [];

    while (this.#buffer.length >= 3) {
      const size = (this.#buffer[0] << 16) | (this.#buffer[1] << 8) | this.#buffer[2];
      if (this.#buffer.length < size + 3) {
        break;
      }

      let frame = this.#buffer.subarray(3, size + 3);
      this.#buffer = this.#buffer.subarray(size + 3);

      if (this.#isFinished) {
        frame = coerceBytes(this.decrypt(frame));
        frames.push(decodeNode(frame));
      } else {
        frames.push(copyUint8Array(frame));
      }
    }

    return frames;
  }

  clearBuffer() {
    this.#buffer = Buffer.alloc(0);
  }

  getHash() {
    return copyUint8Array(this.#hash);
  }

  processHandshakeInit(serverEphemeral, serverStaticEncrypted, serverPayloadEncrypted, privateKey) {
    const ephemeral = coerceBytes(serverEphemeral);
    const privateKeyBytes = coerceBytes(privateKey);

    this.authenticate(ephemeral);
    this.mixIntoKey(NoiseCurve.sharedKey(privateKeyBytes, ephemeral));

    const decryptedStatic = coerceBytes(this.decrypt(serverStaticEncrypted));
    this.mixIntoKey(NoiseCurve.sharedKey(privateKeyBytes, decryptedStatic));

    return copyUint8Array(this.decrypt(serverPayloadEncrypted));
  }

  processHandshakeFinish(noisePublicKey, noisePrivateKey, serverEphemeral) {
    const encryptedKey = this.encrypt(noisePublicKey);
    this.mixIntoKey(NoiseCurve.sharedKey(coerceBytes(noisePrivateKey), coerceBytes(serverEphemeral)));
    return encryptedKey;
  }

  #buildIntroHeader(noiseHeader, routingInfo) {
    if (!routingInfo) {
      return Buffer.from(noiseHeader);
    }

    const routing = coerceBytes(routingInfo);
    const header = Buffer.alloc(7);
    header.write('ED', 0, 'utf8');
    header.writeUInt8(0, 2);
    header.writeUInt8(1, 3);
    header.writeUInt8(routing.length >> 16, 4);
    header.writeUInt16BE(routing.length & 0xffff, 5);
    return Buffer.concat([header, routing, noiseHeader]);
  }

  #encodeFrameBytes(data) {
    const payload = coerceBytes(data);
    const intro = this.#sentIntro ? Buffer.alloc(0) : this.#introHeader;
    const frame = Buffer.alloc(intro.length + 3 + payload.length);

    if (!this.#sentIntro) {
      intro.copy(frame, 0);
      this.#sentIntro = true;
    }

    const offset = intro.length;
    frame.writeUInt8(payload.length >> 16, offset);
    frame.writeUInt16BE(payload.length & 0xffff, offset + 1);
    payload.copy(frame, offset + 3);

    return copyUint8Array(frame);
  }

  #aesEncrypt(plaintext, key, iv, additionalData) {
    return copyUint8Array(aesEncryptGCM(plaintext, key, iv, additionalData));
  }

  #aesDecrypt(ciphertext, key, iv, additionalData) {
    return copyUint8Array(aesDecryptGCM(ciphertext, key, iv, additionalData));
  }
}

export function encodeNode(nodeVal) {
  return copyUint8Array(encodeBinaryNode(normalizeEncodingNode(nodeVal)));
}

export function decodeNode(data) {
  try {
    const input = coerceBytes(data, 'data');
    const decompressed = (input[0] & 2) === 2 ? inflateSync(input.subarray(1)) : input.subarray(1);
    const decoded = decodeDecompressedBinaryNode(Buffer.from(decompressed), binaryConstants);
    return new InternalBinaryNode(normalizeDecodedNode(decoded));
  } catch (error) {
    if (String(error).includes('end of stream')) {
      throw new Error('Unexpected end of binary data');
    }

    throw error;
  }
}

export function generateKeyPair() {
  const pair = libSignalCurve.generateKeyPair();
  return normalizeKeyPair(pair);
}

export function generateIdentityKeyPair() {
  return generateKeyPair();
}

export function generateRegistrationId() {
  return randomBytes(2).readUInt16LE(0) & 0x3fff;
}

export function calculateAgreement(publicKeyBytes, privateKeyBytes) {
  const publicKey = coerceBytes(publicKeyBytes, 'public_key');
  const privateKey = coerceBytes(privateKeyBytes, 'private_key');

  if (![32, 33].includes(publicKey.length)) {
    throw new Error('Invalid public key');
  }

  if (privateKey.length !== 32) {
    throw new Error('Incorrect private key length');
  }

  return copyUint8Array(libSignalCurve.calculateAgreement(publicKey, privateKey));
}

export function calculateSignature(privateKeyBytes, message) {
  if (privateKeyBytes === null || typeof privateKeyBytes === 'undefined') {
    throw new Error('Invalid private key type');
  }

  const privateKey = coerceBytes(privateKeyBytes, 'private_key');
  const payload = coerceBytes(message, 'message');

  if (privateKey.length === 0) {
    throw new Error('Invalid private key type');
  }

  if (privateKey.length !== 32) {
    throw new Error('Incorrect private key length');
  }

  return copyUint8Array(libSignalCurve.calculateSignature(privateKey, payload));
}

export function verifySignature(publicKeyBytes, message, signature) {
  const publicKey = coerceBytes(publicKeyBytes, 'public_key');
  const payload = coerceBytes(message, 'message');
  const sig = coerceBytes(signature, 'signature');

  if (![32, 33].includes(publicKey.length)) {
    throw new Error('Invalid public key');
  }

  if (sig.length !== 64) {
    throw new Error('Invalid signature');
  }

  return libSignalCurve.verifySignature(publicKey, payload, sig);
}

export function getPublicFromPrivateKey(privateKeyBytes) {
  const privateKey = coerceBytes(privateKeyBytes, 'private_key');
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes long');
  }

  const publicKey = encodeEd25519Point(ed25519MultiplyBase(privateKey));
  return Uint8Array.of(5, ...publicKey);
}

export function generateSignedPreKey(identityKeyPair, signedKeyId) {
  const pair = normalizeKeyPair(identityKeyPair, 'identityKeyPair');
  const signed = libSignalKeyHelper.generateSignedPreKey(
    {
      pubKey: Buffer.from(pair.pubKey),
      privKey: Buffer.from(pair.privKey),
    },
    Number(signedKeyId),
  );

  return normalizeSignedPreKey(signed);
}

export function generatePreKey(keyId) {
  return normalizePreKey(libSignalKeyHelper.generatePreKey(Number(keyId)));
}

export function _serializeIdentityKeyPair(keyPair) {
  const pair = normalizeKeyPair(keyPair);
  const output = Buffer.alloc(2 + pair.pubKey.length + 2 + pair.privKey.length);
  let offset = 0;
  output[offset++] = (1 << 3) | 2;
  output[offset++] = pair.pubKey.length;
  Buffer.from(pair.pubKey).copy(output, offset);
  offset += pair.pubKey.length;
  output[offset++] = (2 << 3) | 2;
  output[offset++] = pair.privKey.length;
  Buffer.from(pair.privKey).copy(output, offset);
  return copyUint8Array(output);
}

export function md5(buffer) {
  return copyUint8Array(createHash('md5').update(coerceBytes(buffer)).digest());
}

export function hkdf(buffer, expandedLength, info = {}) {
  return copyUint8Array(hkdfBytes(buffer, expandedLength, info));
}

export function expandAppStateKeys(keyData) {
  const expanded = hkdfBytes(keyData, 160, { info: 'WhatsApp Mutation Keys' });
  return new ExpandedAppStateKeys({
    indexKey: expanded.subarray(0, 32),
    valueEncryptionKey: expanded.subarray(32, 64),
    valueMacKey: expanded.subarray(64, 96),
    snapshotMacKey: expanded.subarray(96, 128),
    patchMacKey: expanded.subarray(128, 160),
  });
}

export function generateContentMac(operation, data, keyId, key) {
  const opByte = operation === 1 ? 0x01 : 0x02;
  const keyData = Buffer.concat([Buffer.from([opByte]), coerceBytes(keyId)]);
  const last = Buffer.alloc(8);
  last[last.length - 1] = keyData.length;
  return copyUint8Array(hmac('sha512', coerceBytes(key), Buffer.concat([keyData, coerceBytes(data), last])).subarray(0, 32));
}

export function generateSnapshotMac(ltHash, version, name, key) {
  return copyUint8Array(
    hmac(
      'sha256',
      coerceBytes(key),
      Buffer.concat([coerceBytes(ltHash), u64be(version), Buffer.from(name, 'utf8')]),
    ),
  );
}

export function generatePatchMac(snapshotMac, valueMacs, version, name, key) {
  return copyUint8Array(
    hmac(
      'sha256',
      coerceBytes(key),
      Buffer.concat([
        coerceBytes(snapshotMac),
        ...(valueMacs ?? []).map(value => coerceBytes(value)),
        u64be(version),
        Buffer.from(name, 'utf8'),
      ]),
    ),
  );
}

export function generateIndexMac(indexBytes, key) {
  return copyUint8Array(hmac('sha256', coerceBytes(key), coerceBytes(indexBytes)));
}

export function getEnabledFeatures() {
  return { ...OPTIONAL_FEATURES };
}

export function getWAConnHeader() {
  return copyUint8Array(NOISE_WA_HEADER);
}

export function setLogger(logger) {
  currentLogger = logger;
}

export function updateLogger(logger) {
  currentLogger = logger;
}

export function hasLogger() {
  return Boolean(currentLogger);
}

export function logMessage(level, message) {
  if (!currentLogger) {
    return;
  }

  const method = parseLoggerMethod(level);
  currentLogger[method]?.({ target: 'whatsapp-rust-bridge' }, message);
}

function unavailable(name) {
  throw new Error(`${name} no esta disponible en la version sin WebAssembly.`);
}

export function addStickerMetadata() {
  unavailable('addStickerMetadata');
}

export function getStickerMetadata() {
  unavailable('getStickerMetadata');
}

export function extractImageThumb() {
  unavailable('extractImageThumb');
}

export function generateProfilePicture() {
  unavailable('generateProfilePicture');
}

export function getImageDimensions() {
  unavailable('getImageDimensions');
}

export function convertToWebP() {
  unavailable('convertToWebP');
}

export function processImage() {
  unavailable('processImage');
}

export function generateAudioWaveform() {
  unavailable('generateAudioWaveform');
}

export async function getAudioDuration() {
  unavailable('getAudioDuration');
}
