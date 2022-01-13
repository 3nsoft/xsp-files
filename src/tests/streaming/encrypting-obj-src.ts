/*
 Copyright (C) 2016 - 2020, 2022 3NSoft Inc.
 
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 See the GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along with
 this program. If not, see <http://www.gnu.org/licenses/>.
*/

import { itAsync, beforeEachAsync } from '../../test-lib/async-jasmine';
import { KEY_LENGTH, NONCE_LENGTH, makeSegmentsWriter, makeSegmentsReader, makeObjSourceFromArrays, makeEncryptingObjSource } from '../../lib/index';
import { mockCryptor, getRandom, compare, toOneArray } from '../../test-lib/test-utils';
import { sourceFromArray } from '../../test-lib/array-backed-byte-streaming';
import { readSegsSequentially } from '../../test-lib/segments-test-utils';

const cryptor = mockCryptor();

describe(`Function makeObjSourceFromArrays`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;
	const payloadFormat = 2;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	itAsync(`makes source that encrypts given byte arrays`, async () => {
		const testGeom: { len: number, splitPositions: number[] }[] = [
			{ len: 5, splitPositions: [] },
			{ len: 5, splitPositions: [ 3 ] },
			{ len: 256, splitPositions: [ 100, 200 ] },
			{ len: 256, splitPositions: [ 100, 200, 200 ] }, // one empty array
			{ len: 4*1024+250, splitPositions: [ 1000, 4*1024+150 ] }
		];

		for (const { len, splitPositions } of testGeom) {
			const content = await getRandom(len);
			const contentChunks = splitArray(content, splitPositions);

			// create encrypting source
			const segWriter = await makeSegmentsWriter(
				key, zerothNonce, version,
				{ type: 'new', segSize: 16, payloadFormat },
				getRandom, cryptor);
			const src = await makeObjSourceFromArrays(contentChunks, segWriter);
			expect(await src.segSrc.getSize()).not.toBeUndefined();

			// read encrypted bytes from an object source
			const header = await src.readHeader();
			await src.segSrc.seek(1).then(() => fail(
				`This source implementation can't seek`), () => {});
			const allSegs = await src.segSrc.read(undefined);
			expect(allSegs).not.toBeUndefined();

			const reader = await makeSegmentsReader(
				key, zerothNonce, version, header, cryptor);
			const readContent = await readSegsSequentially(reader, allSegs!);

			compare(readContent, content,
				`Testing content length ${len}. Bytes decrypted from segments should be the same as original encrypted bytes`);
		}

		for (const { len, splitPositions } of testGeom) {
			const content = await getRandom(len);
			const contentChunks = splitArray(content, splitPositions);

			// create encrypting source
			const segWriter = await makeSegmentsWriter(
				key, zerothNonce, version,
				{ type: 'new', segSize: 16, payloadFormat },
				getRandom, cryptor);
			const src = await makeObjSourceFromArrays(contentChunks, segWriter);

			// read encrypted bytes from an object source in chunks
			const header = await src.readHeader();
			const srcSize = await src.segSrc.getSize();
			expect(srcSize.isEndless).toBe(false);
			const readChunkSizes = splitNumber(srcSize.size, splitPositions)
			.filter(n => (n > 0));
			const chunkedReads: Uint8Array[] = [];
			for (let chunkLen of readChunkSizes) {
				const chunk = (await src.segSrc.read(chunkLen))!;
				chunkedReads.push(chunk);
			}
			const allSegs = toOneArray(chunkedReads);

			const reader = await makeSegmentsReader(
				key, zerothNonce, version, header, cryptor);
			const readContent = await readSegsSequentially(reader, allSegs);

			compare(readContent, content,
				`Testing content length ${len}. Bytes decrypted from segments should be the same as original encrypted bytes`);
		}
	});

	itAsync(`makes source that works for no arrays`, async () => {
		const segWriter = await makeSegmentsWriter(
			key, zerothNonce, version,
			{ type: 'new', segSize: 16, payloadFormat },
			getRandom, cryptor);
		const src = await makeObjSourceFromArrays([], segWriter);
		
		const srcSize = await src.segSrc.getSize();
		expect(srcSize.isEndless).toBe(false);
		expect(srcSize.size).toBe(0);
		expect(await src.segSrc.read(undefined)).toBeUndefined(`cause there is no bytes`);
		
		const header = await src.readHeader();
		
		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		expect(segReader.segmentsLength).toBe(0);
	});

});

function splitArray(arr: Uint8Array, splitPositions: number[]): Uint8Array[] {
	splitPositions.sort((a,b) => ((a < b) ? -1 : ((a > b) ? 1 : 0)));
	const chunks = [ arr ];
	let tail = arr;
	let tailOfs = 0;
	for (const cutPos of splitPositions) {
		const head = tail.subarray(0, cutPos-tailOfs);
		tail = tail.subarray(head.length);
		tailOfs += head.length;
		chunks[chunks.length-1] = head;
		chunks.push(tail);
	}
	return chunks;
}

function splitNumber(x: number, splitPositions: number[]): number[] {
	splitPositions.sort((a,b) => ((a < b) ? -1 : ((a > b) ? 1 : 0)));
	const chunks = [ x ];
	let tail = x;
	let tailOfs = 0;
	for (const cutPos of splitPositions) {
		const head = cutPos-tailOfs;
		tail -= head;
		tailOfs += head;
		chunks[chunks.length-1] = head;
		chunks.push(tail);
	}
	return chunks;
}

describe(`Function makeEncryptingObjSource`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;
	const payloadFormat = 2;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	itAsync(`encrypts non-empty byte source`, async () => {
		for (const len of [ 256, 4*1024+250, 2*4*1024+950, 100438 ]) {
			const content = await getRandom(len);

			// byte source from content bytes
			const byteSrc = sourceFromArray(content);

			const segWriter = await makeSegmentsWriter(
				key, zerothNonce, version,
				{ type: 'new', segSize: 16, payloadFormat },
				getRandom, cryptor);
			
			const src = await makeEncryptingObjSource(byteSrc, segWriter);
			
			const segsSize = await src.segSrc.getSize();
			expect(segsSize.isEndless).toBe(false);
			expect(segsSize.size).toBeGreaterThan(0);
			
			const header = await src.readHeader();
			
			const encryptedChunks: Uint8Array[] = [];
			const readAmount = Math.floor(len/5);
			for (let i=0; i<5; i+=1) {
				encryptedChunks.push(
					(await src.segSrc.read(readAmount))!);
			}
			encryptedChunks.push(
				(await src.segSrc.read(undefined))!);
			expect(await src.segSrc.read(undefined)).toBeUndefined();

			const encrypted = toOneArray(encryptedChunks);
			expect(encrypted.length).toBe(segsSize.size);
			
			const segReader = await makeSegmentsReader(
				key, zerothNonce, version, header, cryptor);
			expect(segReader.isEndlessFile).toBe(false, `Making object from a byte array in one step, naturally, should produce an object with finite size.`);
			const readContent = await readSegsSequentially(segReader, encrypted);
			compare(readContent, content,
				`Bytes decrypted from segments should be the same as original ${content.length} encrypted bytes`);
		}
	});

	itAsync(`works for zero length byte source`, async () => {

		// packing an empty byte source (empty file situation)
		const byteSrc = sourceFromArray(new Uint8Array(0));

		const segWriter = await makeSegmentsWriter(
			key, zerothNonce, version,
			{ type: 'new', segSize: 16, payloadFormat },
			getRandom, cryptor);
		const src = await makeEncryptingObjSource(byteSrc, segWriter);

		const srcSize = await src.segSrc.getSize();
		expect(srcSize.isEndless).toBe(false);
		expect(srcSize.size).toBe(0);
		expect(await src.segSrc.read(undefined)).toBeUndefined();

		const header = await src.readHeader();

		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		expect(segReader.segmentsLength).toBe(0);
	});

	itAsync(`produces seekable source`, async () => {
		const content = await getRandom(2*4*1024+950);
		const initByteSrc = sourceFromArray(content);

		const newSegWriter = await makeSegmentsWriter(
			key, zerothNonce, version,
			{ type: 'new', segSize: 16, payloadFormat },
			getRandom, cryptor);

		const initSrc = await makeEncryptingObjSource(initByteSrc, newSegWriter);

		// encrypt without seeking, to compare to seek-and-encrypt
		const header = await initSrc.readHeader();
		const segs = await initSrc.segSrc.read(undefined);

		// seeking back is not allowed
		await initSrc.segSrc.seek((await initSrc.segSrc.getPosition()) - 2).then(
			() => fail(`Current implementation doesn't allow seeking back`),
			() => {});

		// seeking forward works
		for (const offset of [ 0, 4*1024, 4*1024+15 ]) {
			const restartedSegWriter = await makeSegmentsWriter(
				key, zerothNonce, version,
				{ type: 'restart', header },
				getRandom, cryptor);
			const byteSrc = sourceFromArray(content);
			const src = await makeEncryptingObjSource(byteSrc, restartedSegWriter);
			await src.segSrc.seek!(offset);
			const chunk = await src.segSrc.read(undefined);
			compare(chunk!, segs!.subarray(offset), `chunk encrypted after seek should be exactly the same as bytes in initial segments`);
		}
	});

});
