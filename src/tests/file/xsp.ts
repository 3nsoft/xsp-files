/* Copyright(c) 2013 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Testing xsp file format functions.
 */

import { getRandom, compare } from '../test-utils';
import * as xsp from '../../lib/index';
import { secret_box } from 'ecma-nacl';

/**
 * Test encrypting and packing dataLen of bytes of data into xsp file
 * with segment size segSizein256bs with a simple, single chain header.
 */
function testSingleChainHeader(dataLen: number, segSizein256bs: number) {

	var data = getRandom(dataLen);
	var masterKey = getRandom(32);
	var mkeyEncr = secret_box.formatWN.makeEncryptor(
		masterKey, getRandom(24));
	var fkeyHolder = xsp.makeNewFileKeyHolder(mkeyEncr, getRandom);

	// initialize writer
	var writer = fkeyHolder.newSegWriter(segSizein256bs, getRandom);
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeNull();
	expect(writer.segmentsLength()).toBeNull();
	expect(writer.numberOfSegments()).toBeNull();
	writer.setContentLength(dataLen);
	expect(writer.isEndlessFile()).toBe(false)
	expect(writer.contentLength()).toBe(dataLen);
	var segmentsLen = writer.segmentsLength();
	
	// pack file header
	expect(writer.isHeaderModified()).toBe(true);
	var fileHeader = writer.packHeader();
	expect(writer.isHeaderModified()).toBe(false);

	// pack segments
	var fileSegments: Uint8Array[] = [];
	var offset = 0;
	var segInd = 0;
	var encRes: { dataLen: number; seg: Uint8Array };
	while (offset < data.length) {
		encRes = writer.packSeg(data.subarray(offset), segInd);
		offset += encRes.dataLen;
		segInd += 1;
		fileSegments.push(encRes.seg);
	}
	expect(writer.numberOfSegments()).toBe(fileSegments.length);
	
	// check total segments length
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) {
		offset += fileSegments[i].length;
	}
	expect(offset).toBe(segmentsLen);
	
	// test reseting writer
	writer.reset();
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeNull();
	expect(writer.segmentsLength()).toBeNull();
	
	// wipe key bytes from memory
	writer.destroy();
	writer = null;

	// combine all parts into one xsp file
	var fileStart = xsp.generateXSPFileStart(segmentsLen);
	var completeFile = new Uint8Array(
		fileStart.length + segmentsLen + fileHeader.length);
	completeFile.set(fileStart);
	offset = fileStart.length;
	for (var i=0; i<fileSegments.length; i+=1) {
		completeFile.set(fileSegments[i], offset);
		offset += fileSegments[i].length;
	}
	completeFile.set(fileHeader, offset);
	fileStart = null;
	fileHeader = null;
	var numOfSegment = fileSegments.length;
	fileSegments = null;
	
	// Note: at this point completeFile contains xsp file, which
	// contains both segments and a file header. In some situations single file
	// is a good solution. In other situations segments and a header better
	// stored in separate files.

	// read xsp file
	var segsEnd = xsp.getXSPHeaderOffset(completeFile);
	var reader = fkeyHolder.segReader(completeFile.subarray(segsEnd));
	expect(reader.isEndlessFile()).toBe(false);
	expect(reader.contentLength()).toBe(dataLen);
	expect(reader.segmentsLength()).toBe(segmentsLen);
	expect(reader.numberOfSegments()).toBe(numOfSegment);
	offset = xsp.SEGMENTS_OFFSET;
	var segInd = 0;
	var dataParts: Uint8Array[] = [];
	var decRes: { data: Uint8Array; segLen: number; };
	while (offset < segsEnd) {
		decRes = reader.openSeg(completeFile.subarray(offset), segInd);
		offset += decRes.segLen;
		segInd += 1;
		dataParts.push(decRes.data);
	}
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) { offset += dataParts[i].length; }
	var completeReconstrData = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) {
		completeReconstrData.set(dataParts[i], offset);
		offset += dataParts[i].length;
	}
	compare(completeReconstrData, data,
		"Reconstructed data is not the same as original");

}

/**
 * Test encrypting and packing dataLen bytes of data into xsp file with
 * segment size segSizein256bs of endless nature
 */
function testEndlessFile(dataLen: number, segSizein256bs: number) {

	var data = getRandom(dataLen);
	var masterKey = getRandom(32);
	var mkeyEncr = secret_box.formatWN.makeEncryptor(
		masterKey, getRandom(24));
	var fkeyHolder = xsp.makeNewFileKeyHolder(mkeyEncr, getRandom);
//	var mkeyDecr = nacl.secret_box.formatWN.makeDecryptor(masterKey);

	// initialize writer
	var writer = fkeyHolder.newSegWriter(segSizein256bs, getRandom);
	expect(writer.isHeaderModified()).toBe(true);
	expect(writer.isEndlessFile()).toBe(true);
	expect(writer.contentLength()).toBeNull();
	expect(writer.segmentsLength()).toBeNull();
	expect(writer.numberOfSegments()).toBeNull();
	
	// pack file header
	var fileHeader = writer.packHeader();

	// pack segments
	var fileSegments: Uint8Array[] = [];
	var offset = 0;
	var segInd = 0;
	var encRes: { dataLen: number; seg: Uint8Array };
	while (offset < data.length) {
		encRes = writer.packSeg(data.subarray(offset), segInd);
		offset += encRes.dataLen;
		segInd += 1;
		fileSegments.push(encRes.seg);
	}
	
	// wipe key bytes from memory
	writer.destroy();
	writer = null;

	// combine all parts into one xsp file
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) {
		offset += fileSegments[i].length;
	}
	var fileStart = xsp.generateXSPFileStart(offset);
	offset += fileStart.length;
	var completeFile = new Uint8Array(offset + fileHeader.length);
	completeFile.set(fileStart);
	offset = fileStart.length;
	for (var i=0; i<fileSegments.length; i+=1) {
		completeFile.set(fileSegments[i], offset);
		offset += fileSegments[i].length;
	}
	completeFile.set(fileHeader, offset);
	fileStart = null;
	fileHeader = null;
	fileSegments = null;
	
	// Note: at this point completeFile contains xsp file, which
	// contains both segments and a file header. In some situations single file
	// is a good solution. In other situations segments and a header better
	// stored in separate files.

	// read xsp file (endless type)
	var segsEnd = xsp.getXSPHeaderOffset(completeFile);
	var reader = fkeyHolder.segReader(completeFile.subarray(segsEnd));
	expect(reader.isEndlessFile()).toBe(true);
	expect(reader.contentLength()).toBeNull();
	expect(reader.segmentsLength()).toBeNull();
	expect(reader.numberOfSegments()).toBeNull();
	offset = xsp.SEGMENTS_OFFSET;
	var segInd = 0;
	var dataParts: Uint8Array[] = [];
	var decRes: { data: Uint8Array; segLen: number; };
	while (offset < segsEnd) {
		// Note that by placing segsEnd, we make sure that last segment
		// covers array from start to end, giving implicitly info about
		// length of the last segment. In a finite file, segment length
		// comes from a header, but in an infinit case, length of the
		// last segment is an unknown for reader.
		decRes = reader.openSeg(completeFile.subarray(offset, segsEnd), segInd);
		offset += decRes.segLen;
		segInd += 1;
		dataParts.push(decRes.data);
	}
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) { offset += dataParts[i].length; }
	var completeReconstrData = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) {
		completeReconstrData.set(dataParts[i], offset);
		offset += dataParts[i].length;
	}
	compare(completeReconstrData, data,
		"Reconstructed data is not the same as original");

}

describe('Packing and reading single chain file', () => {

	// 16K segment size
	let segSizein256bs = 64;
	let testDataLens = [ 0, 1, 16, 64*256-90, 64*256-16, 64*256, 3*64*256 ];
	for (let dataLen of testDataLens) {
		it(`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => { testSingleChainHeader(dataLen, segSizein256bs); });
	}

});

describe('Packing and reading endless file', () => {

	// 16K segment size
	let segSizein256bs = 64;
	let testDataLens = [ 1, 16, 64*256-90, 64*256-16, 64*256, 3*64*256 ];
	for (let dataLen of testDataLens) {
		it(`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => { testEndlessFile(dataLen, segSizein256bs); });
	}

});

// TODO add tests of a file splicing, when it will be done.


