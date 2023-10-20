import { it, expect } from 'vitest';
import { generateMnemonic, mnemonicToSeed } from '../';

it('Generate a mnemonics:  128 | 160 | 192 | 224 | 256 bits', async () => {
	const mnemonic128 = await generateMnemonic(128);
	expect(mnemonic128.split(' ')).toHaveLength(12);

	const mnemonic160 = await generateMnemonic(160);
	expect(mnemonic160.split(' ')).toHaveLength(15);

	const mnemonic192 = await generateMnemonic(192);
	expect(mnemonic192.split(' ')).toHaveLength(18);

	const mnemonic224 = await generateMnemonic(224);
	expect(mnemonic224.split(' ')).toHaveLength(21);

	const mnemonic256 = await generateMnemonic(256);
	expect(mnemonic256.split(' ')).toHaveLength(24);
});

it('Two different mnemonics should not be equal', async () => {
	const mnemonic1 = await generateMnemonic();
	const mnemonic2 = await generateMnemonic();

	expect(mnemonic1).not.toEqual(mnemonic2);
});

it('Tests mnemonic to seed consistency', async () => {
	const mnemonic = await generateMnemonic();

	const seed1 = await mnemonicToSeed(mnemonic);
	const seed2 = await mnemonicToSeed(mnemonic);

	const num1 = Array.from(new Uint8Array(seed1)).reduce((acc, value) => acc + value, 0);
	const num2 = Array.from(new Uint8Array(seed2)).reduce((acc, value) => acc + value, 0);

	expect(num1).toEqual(num2);
});

it('Tests mnemonic to seed consistency with passphrase', async () => {
	const mnemonic = await generateMnemonic();

	const seed1 = await mnemonicToSeed(mnemonic, 'passphrase');
	const seed2 = await mnemonicToSeed(mnemonic, 'passphrase');

	const num1 = Array.from(new Uint8Array(seed1)).reduce((acc, value) => acc + value, 0);
	const num2 = Array.from(new Uint8Array(seed2)).reduce((acc, value) => acc + value, 0);

	expect(num1).toEqual(num2);
});

it('Tests mnemonic to seed consistency with different passphrase', async () => {
	const mnemonic = await generateMnemonic();

	const seed1 = await mnemonicToSeed(mnemonic, 'passphrase1');
	const seed2 = await mnemonicToSeed(mnemonic, 'passphrase2');

	const num1 = Array.from(new Uint8Array(seed1)).reduce((acc, value) => acc + value, 0);
	const num2 = Array.from(new Uint8Array(seed2)).reduce((acc, value) => acc + value, 0);

	expect(num1).not.toEqual(num2);
});
