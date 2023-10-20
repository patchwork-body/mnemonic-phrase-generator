import bip39WordList from '../wordlist.english.json';

// https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch05.asciidoc#generating-mnemonic-words
export const generateMnemonic = async (entropySize: 128 | 160 | 192 | 224 | 256 = 256) => {
	const entropy = crypto.getRandomValues(new Uint8Array(entropySize / 8));
	const sha256 = await crypto.subtle.digest('SHA-256', entropy);

	const checksumBitMask = {
		128: 0b11110000, // 4 bits
		160: 0b11111000, // 5 bits
		192: 0b11111100, // 6 bits
		224: 0b11111110, // 7 bits
		256: 0b11111111, // 8 bits
	}[entropySize];

	const checksum = new Uint8Array(sha256.slice(0, 1))[0] & checksumBitMask;
	const checksumBinaryString = checksum.toString(2).padStart(8, '0').slice(0, entropySize / 32);

	let entropyBinaryString = ''
	entropy.forEach((byte) => {
		entropyBinaryString += byte.toString(2).padStart(8, '0');
	});

	const entropyWithChecksum = entropyBinaryString + checksumBinaryString;

	// 11 bits per word
	const segments = entropyWithChecksum.match(/.{1,11}/g) || [];

	return segments
		.map((segment) => {
			const wordIndex = parseInt(segment, 2);
			return bip39WordList[wordIndex];
		})
		.join(' ');
};

// https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch05.asciidoc#fig_5_7
export const mnemonicToSeed = async (mnemonic: string, passphrase = '') => {
	const mnemonicBuffer = new TextEncoder().encode(mnemonic.normalize('NFKD'));
	const saltBuffer = new TextEncoder().encode(`mnemonic${passphrase.normalize('NFKD')}`);

	return crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: saltBuffer,
			iterations: 2048,
			hash: 'SHA-512',
		},
		await crypto.subtle.importKey('raw', mnemonicBuffer, 'PBKDF2', false, ['deriveBits']),
		512,
	);
};
