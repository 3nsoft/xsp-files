/*
 Copyright(c) 2017 - 2018 3NSoft Inc.
 
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 See the GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along with
 this program. If not, see <http://www.gnu.org/licenses/>. */

import { getRandom, getRandomSync, mockCryptor }
	from '../../test-lib/test-utils';
import { packSegments, readSegsSequentially } from '../segments/xsp';
import { calculateNonce, NONCE_LENGTH, KEY_LENGTH, compareVectors,
	makeSegmentsWriter, makeSegmentsReader }
	from '../../lib/index';
import { itAsync } from '../../test-lib/async-jasmine';

const cryptor = mockCryptor();
const segSizein256bs = 16;

describe('Header nonce', () => {

	const data = getRandomSync(345);
	const key = getRandomSync(KEY_LENGTH);
	const zerothHeaderNonce = getRandomSync(NONCE_LENGTH);
	const version = 7;
	
	itAsync('is related to initial zeroth nonce via version', async () => {
		const writer = await makeSegmentsWriter(
			key, zerothHeaderNonce, version,
			{ type: 'new', segSize: segSizein256bs },
			getRandom, cryptor);

		const segs = await packSegments(writer, data);
		const header = await writer.packHeader();
		
		const verNonce = header.subarray(0, NONCE_LENGTH);
		const zNonce = calculateNonce(verNonce, -version);
		expect(compareVectors(zNonce, zerothHeaderNonce)).toBe(true);

		const reader = await makeSegmentsReader(
			key, zNonce, version, header, cryptor);
		const d = await readSegsSequentially(reader, segs);
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