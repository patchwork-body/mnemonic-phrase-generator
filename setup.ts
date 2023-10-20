import crypto from 'node:crypto';

type FixedCrypto = Crypto & {
	getRandomValues: <T extends Uint8Array>(array: T) => T;
};

globalThis.crypto = crypto as FixedCrypto;
