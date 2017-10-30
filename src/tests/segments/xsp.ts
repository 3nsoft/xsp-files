/* Copyright(c) 2013 - 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Testing xsp file format functions.
 */

import { getRandom, compare, mockCryptor, combineByteArrays,
	totalLengthOfByteArrays }
	from '../test-utils';
import { KEY_LENGTH, NONCE_LENGTH, makeSegmentsReader, makeSegmentsWriter,
	makeSplicingSegmentsWriter, SegmentsReader, SegmentsWriter }
	from '../../lib/index';
import { itAsync } from '../async-jasmine';

const cryptor = mockCryptor();

/**
 * Test encrypting and packing dataLen of bytes of data into xsp file
 * with segment size segSizein256bs with a simple, single chain header.
 */
async function testSingleChainHeader(dataLen: number, segSizein256bs: number) {

	const data = getRandom(dataLen);
	const key = getRandom(KEY_LENGTH);
	const zerothHeaderNonce = getRandom(NONCE_LENGTH);
	const version = 7;
	
	// initialize writer
	const writer = makeSegmentsWriter(
		key, zerothHeaderNonce, version, segSizein256bs, getRandom, cryptor);
	expect(writer.version).toBe(version);
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeUndefined();
	expect(writer.segmentsLength()).toBeUndefined();
	expect(writer.numberOfSegments()).toBeUndefined();
	writer.setContentLength(dataLen);
	expect(writer.isEndlessFile()).toBe(false)
	expect(writer.contentLength()).toBe(dataLen);
	expect(typeof writer.numberOfSegments()).toBe('number');
	const segmentsLen = writer.segmentsLength()!;
	
	// pack file header
	expect(writer.isHeaderModified()).toBe(true);
	const fileHeader = await writer.packHeader();
	expect(writer.isHeaderModified()).toBe(false);

	// pack segments
	const fileSegments = await packSegments(writer, data);
	expect(fileSegments.length).toBe(writer.numberOfSegments()!);
	
	// check total segments length
	expect(totalLengthOfByteArrays(fileSegments)).toBe(segmentsLen);
	
	// test reseting writer
	writer.reset();
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeUndefined();
	expect(writer.segmentsLength()).toBeUndefined();
	
	// wipe key bytes from memory
	writer.destroy();

	// In real life segments come in some byte array. All that can be assumed is
	// that segments are ordered there: 1st, 2nd, etc.
	const allSegs = combineByteArrays(fileSegments);
	
	// read data from encrypted segments
	const reader = await makeSegmentsReader(
		key, zerothHeaderNonce, version, fileHeader, cryptor);
	expect(reader.version).toBe(version);
	expect(reader.isEndlessFile()).toBe(false);
	expect(reader.contentLength()).toBe(dataLen);
	expect(reader.segmentsLength()).toBe(segmentsLen);
	expect(reader.numberOfSegments()).toBe(fileSegments.length);
	const dataFromSegs = await readSegsSequentially(reader, allSegs);
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	compare(combineByteArrays(dataFromSegs), data,
		"Reconstructed data is not the same as original");

	// ensure that incorrect version fails the check
	try {
		await makeSegmentsReader(
			key, zerothHeaderNonce, version + 1, fileHeader, cryptor);
		fail(`Version checking creation of a reader must fail a wrong version`);
	} catch (err) {}


	// there is an option to create reader without checking version
	try {
		await makeSegmentsReader(
			key, undefined, version + 1, fileHeader, cryptor);
	} catch (err) {
		fail(`Creation of a reader ignores version, when zeroth nonce is not given`);
	}

}

export async function packSegments(writer: SegmentsWriter, data: Buffer):
		Promise<Uint8Array[]> {
	const segs: Uint8Array[] = [];
	let offset = 0;
	let segInd = 0;
	let encRes: { dataLen: number; seg: Uint8Array };
	while (offset < data.length) {
		encRes = await writer.packSeg(data.subarray(offset), segInd);
		offset += encRes.dataLen;
		segInd += 1;
		segs.push(encRes.seg);
	}
	return segs;
}

export async function readSegsSequentially(reader: SegmentsReader,
		allSegs: Uint8Array): Promise<Uint8Array[]> {
	const data: Uint8Array[] = [];
	let offset = 0;
	let segInd = 0;
	let decRes: { data: Uint8Array; segLen: number; };
	while (offset < allSegs.length) {
		decRes = await reader.openSeg(allSegs.subarray(offset), segInd);
		offset += decRes.segLen;
		segInd += 1;
		data.push(decRes.data);
	}
	return data;
}

/**
 * Test encrypting and packing dataLen bytes of data into xsp file with
 * segment size segSizein256bs of endless nature
 */
async function testEndlessFile(dataLen: number, segSizein256bs: number) {

	const data = getRandom(dataLen);
	const key = getRandom(KEY_LENGTH);
	const zerothHeaderNonce = getRandom(NONCE_LENGTH);
	const version = 3;

	// initialize writer
	const writer = makeSegmentsWriter(
		key, zerothHeaderNonce, version, segSizein256bs, getRandom, cryptor);
	expect(writer.version).toBe(version);
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeUndefined();
	expect(writer.segmentsLength()).toBeUndefined();
	expect(writer.numberOfSegments()).toBeUndefined();
	
	// pack file header
	const fileHeader = await writer.packHeader();

	// pack segments
	const fileSegments = await packSegments(writer, data);
	
	// wipe key bytes from memory
	writer.destroy();

	// In real life segments come in some byte array. All that can be assumed is
	// that segments are ordered there: 1st, 2nd, etc.
	const allSegs = combineByteArrays(fileSegments);
	
	// read data from encrypted segments of an endless file
	const reader = await makeSegmentsReader(
		key, zerothHeaderNonce, version, fileHeader, cryptor);
	expect(reader.version).toBe(version);
	expect(reader.isEndlessFile()).toBe(true);
	expect(reader.contentLength()).toBeUndefined();
	expect(reader.segmentsLength()).toBeUndefined();
	expect(reader.numberOfSegments()).toBeUndefined();
	const dataFromSegs = await readSegsSequentially(reader, allSegs);
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	compare(combineByteArrays(dataFromSegs), data,
		"Reconstructed data is not the same as original");

	// ensure that incorrect version fails the check
	try {
		await makeSegmentsReader(
			key, zerothHeaderNonce, version + 1, fileHeader, cryptor);
		fail(`Version checking creation of a reader must fail a wrong version`);
	} catch (err) {}

	// there is an option to create reader without checking version
	try {
		await makeSegmentsReader(
			key, undefined, version + 1, fileHeader, cryptor);
	} catch (err) {
		fail(`Creation of a reader ignores version, when zeroth nonce is not given`);
	}

}

describe('Packing and reading single chain file', () => {

	// 16K segment size
	let segSizein256bs = 64;
	let testDataLens = [ 0, 1, 16, 64*256-90, 64*256-16, 64*256, 3*64*256 ];
	for (let dataLen of testDataLens) {
		itAsync(
			`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => testSingleChainHeader(dataLen, segSizein256bs));
	}

});

describe('Packing and reading endless file', () => {

	// 16K segment size
	let segSizein256bs = 64;
	let testDataLens = [ 1, 16, 64*256-90, 64*256-16, 64*256, 3*64*256 ];
	for (let dataLen of testDataLens) {
		itAsync(
			`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => testEndlessFile(dataLen, segSizein256bs));
	}

});

// TODO add tests of a file splicing, when it is done.


