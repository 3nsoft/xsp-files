/*
 Copyright (C) 2016 - 2020 3NSoft Inc.
 
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

import { itAsync, beforeEachAsync } from '../../test-lib/async-jasmine';
import { makeSegmentsWriter, NONCE_LENGTH, KEY_LENGTH, makeSegmentsReader, makeDecryptedByteSource, ByteSource, makeDecryptedByteSourceWithAttrs, ByteSourceWithAttrs } from '../../lib/index';
import { compare, mockCryptor, getRandom, toOneArray } from '../../test-lib/test-utils';
import { sourceFromArray } from '../../test-lib/array-backed-byte-streaming';
import { packSegments } from '../../test-lib/segments-test-utils';
import { combineV2Content } from '../../test-lib/streams-test-utils';

const cryptor = mockCryptor();

async function encryptContent(
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	content: Uint8Array, attrs?: Uint8Array
): Promise<{ header: Uint8Array; seekableSegsSrc: ByteSource; }> {
	const segWriter = await makeSegmentsWriter(
		key, zerothNonce, version,
		{ type: 'new', segSize: 16, formatWithSections: !!attrs },
		getRandom, cryptor);
	const contentToPack = (attrs ? combineV2Content(attrs, content) : content);
	segWriter.setContentLength(contentToPack.length);
	const header = await segWriter.packHeader();
	const allSegs = await packSegments(segWriter, contentToPack);
	const seekableSegsSrc = sourceFromArray(allSegs);
	return { header, seekableSegsSrc };
}

async function testDecrObjSrc(
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	content: Uint8Array, attrs?: Uint8Array
): Promise<void> {

	const { header, seekableSegsSrc } = await encryptContent(
		key, zerothNonce, version, content, attrs);

	const segReader = await makeSegmentsReader(
		key, zerothNonce, version, header, cryptor);
	if (attrs) {
		expect(segReader.formatVersion).toBe(2);
	} else {
		expect(segReader.formatVersion).toBe(1);
	}

	const decr = (attrs ?
		await makeDecryptedByteSourceWithAttrs(seekableSegsSrc, segReader) :
		makeDecryptedByteSource(seekableSegsSrc, segReader));

	expect((await decr.getSize()).size).toBe(content.length);

	// test decryption in one go
	{
		await decr.seek(0);
		const decryptedBytes = await decr.read(undefined);
		if (content.length === 0) {
			expect(decryptedBytes).toBeUndefined();
			return;
		}
		compare(decryptedBytes!, content);
	}
	
	// test decryption by pieces
	{
		await decr.seek(0);
		const decryptedChunks: Uint8Array[] = [];
		const chunkLen = Math.floor(content.length/5);
		let bytes = await decr.read(chunkLen);
		while (bytes) {
			decryptedChunks.push(bytes);
			bytes = await decr.read(chunkLen);
		}
		compare(toOneArray(decryptedChunks), content);
		
		bytes = await decr.read(10);
		expect(bytes).toBeUndefined();
		bytes = await decr.read(undefined);
		expect(bytes).toBeUndefined();
	}

	if (attrs) {
		const decryptedAttrs = await (decr as ByteSourceWithAttrs).readAttrs();
		compare(decryptedAttrs, attrs);
	}
}

describe(`Function makeDecryptedByteSource`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	itAsync(`produces seekable byte source`, async () => {
		const content = await getRandom(12*1024+3);
		const { header, seekableSegsSrc } = await encryptContent(
			key, zerothNonce, version, content);

		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		const decr = makeDecryptedByteSource(seekableSegsSrc, segReader);

		expect(typeof decr.seek).toBe('function', 'decrypting source should be seekable');
		expect(typeof decr.getPosition).toBe('function');
		expect(await decr.getPosition()).toBe(0);

		let chunk = await decr.read(200);
		compare(chunk!, content.subarray(0, 200));

		await decr.seek(3000);
		expect(await decr.getPosition()).toBe(3000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(3000, 3200));

		await decr.seek(9000);
		expect(await decr.getPosition()).toBe(9000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(9000, 9200));

		await decr.seek(1000);
		expect(await decr.getPosition()).toBe(1000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(1000, 1200));

		chunk = await decr.read(undefined);
		compare(chunk!, content.subarray(1200));
		expect(await decr.read(undefined)).toBeUndefined();

		await decr.seek(0);
		expect(await decr.getPosition()).toBe(0);
		await decr.seek(content.length);
		expect(await decr.getPosition()).toBe(content.length);
	});

	itAsync(`produces source that decrypts empty and non-empty object`, async () => {
		for (const len of [ 0, 256, 4*1024+250, 2*4*1024+950, 100345 ]) {
			const content = await getRandom(len);
			await testDecrObjSrc(key, zerothNonce, version, content);
		}
	});

});

describe(`Function makeDecryptedByteSourceWithAttrs`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	itAsync(`produces seekable byte source with attributes`, async () => {
		const content = await getRandom(12*1024+3);
		const attrs = await getRandom(25);
		const { header, seekableSegsSrc } = await encryptContent(
			key, zerothNonce, version, content, attrs);

		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		const decr = await makeDecryptedByteSourceWithAttrs(
			seekableSegsSrc, segReader);

		expect(typeof decr.seek).toBe('function', 'decrypting source should be seekable');
		expect(typeof decr.getPosition).toBe('function');
		expect(await decr.getPosition()).toBe(0);

		let chunk = await decr.read(200);
		compare(chunk!, content.subarray(0, 200));

		await decr.seek(3000);
		expect(await decr.getPosition()).toBe(3000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(3000, 3200));

		await decr.seek(9000);
		expect(await decr.getPosition()).toBe(9000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(9000, 9200));

		await decr.seek(1000);
		expect(await decr.getPosition()).toBe(1000);
		chunk = await decr.read(200);
		compare(chunk!, content.subarray(1000, 1200));

		chunk = await decr.read(undefined);
		compare(chunk!, content.subarray(1200));
		expect(await decr.read(undefined)).toBeUndefined();

		await decr.seek(0);
		expect(await decr.getPosition()).toBe(0);
		await decr.seek(content.length);
		expect(await decr.getPosition()).toBe(content.length);
	});

	itAsync(`produces source that decrypts empty and non-empty object with attributes`, async () => {
		for (const len of [ 0, 256, 4*1024+250, 2*4*1024+950, 100345 ]) {
			const content = await getRandom(len);
			const attrs = await getRandom(25);
			await testDecrObjSrc(key, zerothNonce, version, content, attrs);
		}
	});

});
