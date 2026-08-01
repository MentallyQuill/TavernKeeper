import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const MAGIC = Buffer.from("TKAT1", "ascii");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

function validateKey(key: Buffer) {
  if (key.length !== KEY_BYTES)
    throw new Error("Artifact encryption key must be exactly 32 bytes.");
}

export function decodeTransportKey(value: string) {
  if (!/^[A-Za-z0-9+/]{43}=$/u.test(value))
    throw new Error("Artifact encryption key must be canonical base64.");
  const key = Buffer.from(value, "base64");
  validateKey(key);
  return key;
}

export function encryptTransport(value: unknown, key: Buffer) {
  validateKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(MAGIC);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([MAGIC, nonce, cipher.getAuthTag(), ciphertext]);
}

export function decryptTransport(encrypted: Buffer, key: Buffer): unknown {
  validateKey(key);
  const minimum = MAGIC.length + NONCE_BYTES + TAG_BYTES + 1;
  if (
    encrypted.length < minimum ||
    !encrypted.subarray(0, MAGIC.length).equals(MAGIC)
  )
    throw new Error("Encrypted artifact has an invalid envelope.");
  const nonceStart = MAGIC.length;
  const tagStart = nonceStart + NONCE_BYTES;
  const ciphertextStart = tagStart + TAG_BYTES;
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    encrypted.subarray(nonceStart, tagStart),
  );
  decipher.setAAD(MAGIC);
  decipher.setAuthTag(encrypted.subarray(tagStart, ciphertextStart));
  const plaintext = Buffer.concat([
    decipher.update(encrypted.subarray(ciphertextStart)),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as unknown;
}
