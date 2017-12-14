/* Copyright(c) 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { getRandom, getRandomSync, mockCryptor, combineByteArrays }
	from '../test-utils';
import { packSegments, readSegsSequentially } from '../segments/xsp';
import { calculateNonce, NONCE_LENGTH, KEY_LENGTH, compareVectors,
	makeSegmentsWriter, makeSegmentsReader }
	from '../../lib/index';
import { itAsync } from '../async-jasmine';

const cryptor = mockCryptor();
const segSizein256bs = 16;

describe('Header nonce', () => {

	const data = getRandomSync(345);
	const key = getRandomSync(KEY_LENGTH);
	const zerothHeaderNonce = getRandomSync(NONCE_LENGTH);
	const version = 7;
	
	itAsync('is related to initial zeroth nonce via version', async () => {
		const writer = await makeSegmentsWriter(
			key, zerothHeaderNonce, version, segSizein256bs, getRandom, cryptor);

		const segs = combineByteArrays(await packSegments(writer, data));
		const header = await writer.packHeader();
		
		const verNonce = header.subarray(0, NONCE_LENGTH);
		const zNonce = calculateNonce(verNonce, -version);
		expect(compareVectors(zNonce, zerothHeaderNonce)).toBe(true);

		const reader = await makeSegmentsReader(
			key, zNonce, version, header, cryptor);
		const d = combineByteArrays(await readSegsSequentially(reader, segs));
		expect(compareVectors(d, data)).toBe(true);
	});
});

describe('Function calculateNonce', () => {

	const zerothNonce = getRandomSync(NONCE_LENGTH);
	
	it('creates nonces, related by version', () => {
		[ 1, 4, 1000, 0xffffffffff34, -1, -4, -1000, -0xffffffffff34 ]
		.forEach(ver => {
			const nVer = calculateNonce(zerothNonce, ver);
			expect(compareVectors(nVer, zerothNonce)).toBe(false,
				`nonce for non-zero version ${ver} should be different from zeroth nonce`);
			const zNonce = calculateNonce(nVer, -ver);
			expect(compareVectors(zNonce, zerothNonce)).toBe(true,
				`should be able to calculate zeroth nonce from nonce for version ${ver}, applying delta ${-ver}`);
		});
	});

	it('delta zero, returns equal nonce', () => {
		const zNonce = calculateNonce(zerothNonce, 0);
		expect(compareVectors(zNonce, zerothNonce)).toBe(true);
		expect(zNonce).not.toBe(zerothNonce);
	});

});