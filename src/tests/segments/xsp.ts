/*
 Copyright(c) 2013 - 2018, 2020 3NSoft Inc.
 
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

/**
 * Testing xsp file format functions.
 */

import { getRandom, compare, mockCryptor, objSrcFromArrays, getRandomSync }
	from '../../test-lib/test-utils';
import { KEY_LENGTH, NONCE_LENGTH, makeSegmentsReader, makeSegmentsWriter,
	SegmentsReader, SegmentsWriter, POLY_LENGTH, ObjSource, ByteSource }
	from '../../lib/index';
import { itAsync, beforeEachAsync } from '../../test-lib/async-jasmine';
import { writerToArray } from '../../test-lib/array-backed-byte-streaming';

const cryptor = mockCryptor();

/**
 * Test encrypting and packing dataLen of bytes of data into xsp file
 * with segment size segSizein256bs with a simple, single chain header.
 */
async function testSingleChainHeader(dataLen: number, segSizein256bs: number) {

	const data = await getRandom(dataLen);
	const key = await getRandom(KEY_LENGTH);
	const zerothHeaderNonce = await getRandom(NONCE_LENGTH);
	const version = 7;
	
	// initialize writer
	const writer = await makeSegmentsWriter(
		key, zerothHeaderNonce, version,
		{ type: 'new', segSize: segSizein256bs },
		getRandom, cryptor);
	expect(writer.version).toBe(version);
	expect(writer.isEndlessFile).toBe(true);
	expect(writer.contentLength).toBeUndefined();
	expect(writer.segmentsLength).toBeUndefined();
	await writer.setContentLength(dataLen);
	expect(writer.isEndlessFile).toBe(false)
	expect(writer.contentLength).toBe(dataLen);
	
	// pack file header
	expect(writer.isHeaderPacked).toBe(false);
	const fileHeader = await writer.packHeader();
	expect(writer.isHeaderPacked).toBe(true);
	await writer.packHeader().then(() => {
		fail(`Packing header second time should throw`);
	}, err => {});

	// pack segments
	const allSegs = await packSegments(writer, data);
	const segmentsLen = writer.segmentsLength!;
	expect(allSegs.length).toBe(segmentsLen);
	
	// wipe key bytes from memory
	writer.destroy();

	// read data from encrypted segments
	const reader = await makeSegmentsReader(
		key, zerothHeaderNonce, version, fileHeader, cryptor);
	expect(reader.version).toBe(version);
	expect(reader.isEndlessFile).toBe(false);
	expect(reader.contentLength).toBe(dataLen);
	expect(reader.segmentsLength).toBe(segmentsLen);
	const dataFromSegs = await readSegsSequentially(reader, allSegs);
	compare(dataFromSegs, data,
		"Reconstructed data is not the same as original");
	
	// wipe key bytes from memory
	reader.destroy();

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

export async function packSegments(writer: SegmentsWriter, data: Uint8Array,
		baseSegs?: ByteSource): Promise<Uint8Array> {
	if (writer.hasBase && !baseSegs) { throw new Error(
		`Source of base segments is not given for packing with writer that has base`); }
	const { completeArray: segs, writer: arrWriter } = writerToArray();
	await arrWriter.setSize(writer.segmentsLength);
	let dataOfs = 0;
	for (const s of writer.segmentInfos()) {
		let pos = s.packedOfs;
		let bytes: Uint8Array;
		if (s.type === 'base') {
			expect(s.baseOfs).toBeGreaterThanOrEqual(0);
			await baseSegs!.seek(s.baseOfs!);
			bytes = (await baseSegs!.read(s.packedLen))!;
		} else if (s.type === 'new') {
			expect(s.needPacking).toBe(true);
			const dataToPack = data.subarray(dataOfs, dataOfs+s.contentLen);
			dataOfs += dataToPack.length;
			if (s.endlessChain) {
				if (dataToPack.length === 0) { break; }
				bytes = await writer.packSeg(dataToPack, s);
				const isLastSeg = (bytes.length < s.packedLen);
				if (isLastSeg) {
					await arrWriter.write(pos, bytes);
					break;
				}
			} else {
				bytes = await writer.packSeg(dataToPack, s);
			}
		} else {
			throw new Error(`Shouldn't get here`);
		}
		expect(bytes.length).toBe(s.packedLen);
		await arrWriter.write(pos, bytes);
	}
	expect(writer.areSegmentsPacked).toBeTruthy(
		`not all segments are packed in ${writer.isEndlessFile ? 'endless' : 'finite'} file`);
	await arrWriter.done();
	return await segs;
}

export async function readSegsSequentially(reader: SegmentsReader,
		allSegs: Uint8Array): Promise<Uint8Array> {
	const contentLength = reader.contentLength;
	const { completeArray: data, writer: arrWriter } = writerToArray();
	await arrWriter.setSize(contentLength);
	if (contentLength === undefined) {
		for (const segInfo of reader.segmentInfos()) {
			const segBytes = allSegs.subarray(
				segInfo.packedOfs, segInfo.packedOfs + segInfo.packedLen);
			if (segBytes.length === 0) { break; }
			const isLastSeg = (segBytes.length < segInfo.packedLen);
			const segContent = await reader.openSeg(segInfo, segBytes);
			if (isLastSeg) {
				expect(segContent.length).toBeLessThan(segInfo.contentLen);
			} else {
				expect(segContent.length).toBe(segInfo.contentLen);
			}
			await arrWriter.write(segInfo.contentOfs, segContent);
			if (isLastSeg) { break; }
		}
	} else {
		for (const segInfo of reader.segmentInfos()) {
			const segBytes = allSegs.subarray(
				segInfo.packedOfs, segInfo.packedOfs + segInfo.packedLen);
			const segContent = await reader.openSeg(segInfo, segBytes);
			expect(segInfo.contentLen).toBe(segContent.length);
			await arrWriter.write(segInfo.contentOfs, segContent);
		}
	}
	await arrWriter.done();
	return await data;
}

async function packEndlessToFormObjSrc(data: Uint8Array, version: number,
		segSizein256bs: number, key: Uint8Array, zerothHeaderNonce: Uint8Array):
		Promise<ObjSource> {
	const writer = await makeSegmentsWriter(
		key, zerothHeaderNonce, version,
		{ type: 'new', segSize: segSizein256bs },
		getRandom, cryptor);
	const header = await writer.packHeader();
	const segs = await packSegments(writer, data);
	return objSrcFromArrays(version, header, segs);
}

/**
 * Test encrypting and packing dataLen bytes of data into xsp file with
 * segment size segSizein256bs of endless nature
 */
async function testEndlessFile(dataLen: number, segSizein256bs: number) {

	const data = await getRandom(dataLen);
	const key = await getRandom(KEY_LENGTH);
	const zerothHeaderNonce = await getRandom(NONCE_LENGTH);
	const version = 3;

	// initialize writer
	const writer = await makeSegmentsWriter(
		key, zerothHeaderNonce, version,
		{ type: 'new', segSize: segSizein256bs },
		getRandom, cryptor);
	expect(writer.version).toBe(version);
	expect(writer.isEndlessFile).toBe(true);
	expect(writer.contentLength).toBeUndefined();
	expect(writer.segmentsLength).toBeUndefined();
	
	// pack file header
	expect(writer.isHeaderPacked).toBe(false);
	const fileHeader = await writer.packHeader();
	expect(writer.isHeaderPacked).toBe(true);
	await writer.packHeader().then(() => {
		fail(`Packing header second time should throw`);
	}, err => {});

	// pack segments
	const allSegs = await packSegments(writer, data);
	
	// wipe key bytes from memory
	writer.destroy();

	// read data from encrypted segments of an endless file
	const reader = await makeSegmentsReader(
		key, zerothHeaderNonce, version, fileHeader, cryptor);
	expect(reader.version).toBe(version);
	expect(reader.isEndlessFile).toBe(true);
	expect(reader.contentLength).toBeUndefined();
	expect(reader.segmentsLength).toBeUndefined();
	const dataFromSegs = await readSegsSequentially(reader, allSegs);
	compare(dataFromSegs, data,
		"Reconstructed data is not the same as original");
	
	// wipe key bytes from memory
	reader.destroy();

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
	const segSizein256bs = 64;
	// const testDataLens = [ 1 ];
	const testDataLens = [ 0, 1, 16, 64*256-80, 64*256, 64*256+56, 3*64*256 ];
	for (const dataLen of testDataLens) {
		itAsync(
			`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => testSingleChainHeader(dataLen, segSizein256bs));
	}

});

describe('Packing and reading endless file', () => {

	// 16K segment size
	const segSizein256bs = 64;
	const testDataLens = [ 0, 1, 16, 64*256-80, 64*256, 64*256+56, 3*64*256 ];
	for (const dataLen of testDataLens) {
		itAsync(
			`test data length ${dataLen}, with segment size ${segSizein256bs*256}`,
			() => testEndlessFile(dataLen, segSizein256bs));
	}

});

async function packAndCheckSplicedBytes(writer: SegmentsWriter, key: Uint8Array,
		zerothHeaderNonce, baseObj: ObjSource, baseData: Uint8Array,
		newData: Uint8Array,
		layout: { src: 'new'|'base'; baseOfs?: number; len: number; }[]):
		Promise<void> {
	// check layout setting, ensuring correct testing
	{
		let baseLen = 0;
		let newLen = 0;
		for (let s of layout) {
			if (s.src === 'base') {
				baseLen += s.len;
				if (s.baseOfs === undefined) { throw new Error(
					`Missing offset in base layout section`); }
			} else if (s.src === 'new') {
				newLen += s.len;
			} else {
				throw new Error(`Unespected value of src field: ${s.src}`);
			}
		}
		if (baseLen > baseData.length) { throw new Error(
			`Base data length ${baseData.length} is smaller to layout's cumulative base data length ${baseLen}`); }
		if (newLen !== newData.length) { throw new Error(
			`New data length ${newData.length} is not equal to layout's cumulative new data length ${newLen}`); }
	}

	// let's assemble writer's version
	const header = await writer.packHeader();
	const packedNewSegs = await packSegments(writer, newData, baseObj.segSrc);

	// let's read writer's version data and check expectations
	const reader = await makeSegmentsReader(
		key, zerothHeaderNonce, writer.version, header, cryptor);
	const data = await readSegsSequentially(reader, packedNewSegs);
	let newOfs = 0;
	let ofs = 0;
	for (let i=0; i<layout.length; i+=1) {
		const s = layout[i];
		const dataChunk = data.subarray(ofs, ofs + s.len);
		ofs += s.len;
		let expectation: Uint8Array;
		if (s.src === 'base') {
			expectation = baseData.subarray(s.baseOfs!, s.baseOfs! + s.len);
		} else {
			expectation = newData.subarray(newOfs, newOfs + s.len);
			newOfs += s.len;
		}
		compare(dataChunk, expectation, `Layout section ${i}`);
	}
}

describe(`SegmentsWriter`, () => {

	const segSizein256bs = 64;
	const segSize = segSizein256bs*256;
	const key = getRandomSync(KEY_LENGTH);
	const zerothHeaderNonce = getRandomSync(NONCE_LENGTH);

	itAsync(`changes from endless to finite, when length is deducible and before header is packed`, async () => {
		const dataLens = [ 3*segSize, 3*(segSize - POLY_LENGTH) ];
		for (const dataLen of dataLens) {
			const data = await getRandom(dataLen);
			const writer = await makeSegmentsWriter(
				key, zerothHeaderNonce, 1,
				{ type: 'new', segSize: segSizein256bs },
				getRandom, cryptor);
			expect(writer.isEndlessFile).toBe(true);
			await packSegments(writer, data);
			if (dataLen % (segSizein256bs*256) === 0) {
				expect(writer.isEndlessFile).toBe(true);
				await writer.setContentLength(dataLen);
				expect(writer.isEndlessFile).toBe(false);
			} else {
				expect(writer.isEndlessFile).toBe(false);
			}
		}
	});

	itAsync(`will auto-change endless of a previous version to finite`, async () => {
		const dataLens = [ 3*segSize, 3*(segSize - POLY_LENGTH) ];
		for (const dataLen of dataLens) {
			const data = await getRandom(dataLen);
			const objV1 = await packEndlessToFormObjSrc(
				data, 1, segSizein256bs, key, zerothHeaderNonce);

			// check that reader sees header as one for endless file
			const reader = await makeSegmentsReader(
				key, zerothHeaderNonce, 1, await objV1.readHeader(), cryptor);
			expect(reader.isEndlessFile).toBe(true);

			// next version writer switches to finite file
			const writer = await makeSegmentsWriter(
				key, zerothHeaderNonce, 2,
				{ type: 'update', base: objV1 },
				getRandom, cryptor);
			expect(writer.isEndlessFile).toBe(false);
			expect(writer.segmentsLength).toBe((await objV1.segSrc.getSize()).size);
			expect(writer.contentLength).toBe(dataLen);
		}
	});

	async function prepObjV1(numOfCompleteSegs: number, lastSegSize: number):
			Promise<{ dataV1: Uint8Array; objV1: ObjSource; }> {
		const dataV1 = await getRandom(10*segSize + 100);
		const objV1 = await packEndlessToFormObjSrc(
			dataV1, 1, segSizein256bs, key, zerothHeaderNonce);
		return { dataV1, objV1 };
	}

	describe(`.setContentLength() changes length`, () => {

		let dataV1: Uint8Array;
		let objV1: ObjSource;
		let writer: SegmentsWriter;

		beforeEachAsync(async () => {
			({ objV1, dataV1 } = await prepObjV1(10, 100));
			writer = await makeSegmentsWriter(
				key, zerothHeaderNonce, 2,
				{ type: 'update', base: objV1 },
				getRandom, cryptor);
		});

		itAsync(`cutting over the last segment` , async () => {
			await writer.setContentLength(10*segSize + 50);
			expect(writer.contentLength).toBe(10*segSize + 50);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(11);
			segs.forEach((s, i) => {
				if (i < 10) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
				} else if (i === 10) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.needPacking).toBe(true);
					expect(s.contentLen).toBe(0);
					expect(s.headBytes! + POLY_LENGTH).toBe(s.packedLen);
				}
			});
			const newBytes = new Uint8Array(0);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 10*segSize + 50 }
				]);
		});

		itAsync(`cutting between segments` , async () => {
			await writer.setContentLength(9*segSize);
			expect(writer.contentLength).toBe(9*segSize);
			const segs3 = Array.from(writer.segmentInfos());
			expect(segs3.length).toBe(9);
			segs3.forEach((s, i) => {
				expect(s.type).toBe('base');
				expect(s.chain).toBe(0);
			});
		});

		itAsync(`cutting over the middle segment` , async () => {
			await writer.setContentLength(5*segSize + 100);
			expect(writer.contentLength).toBe(5*segSize + 100);
			const segs4 = Array.from(writer.segmentInfos());
			expect(segs4.length).toBe(6);
			segs4.forEach((s, i) => {
				if (i < 5) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
				} else if (i === 5) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.needPacking).toBe(true);
					expect(s.contentLen).toBe(0);
					expect(s.headBytes! + POLY_LENGTH).toBe(s.packedLen);
				}
			});
			const newBytes = new Uint8Array(0);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 5*segSize + 100 }
				]);
		});

		itAsync(`cutting and growing to original size` , async () => {
			await writer.setContentLength(5*segSize + 100);
			await writer.setContentLength(10*segSize + 100);
			expect(writer.contentLength).toBe(10*segSize + 100);
			const segs5 = Array.from(writer.segmentInfos());
			expect(segs5.length).toBe(11);
			segs5.forEach((s, i) => {
				if (i < 5) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
				} else if (i === 5) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.needPacking).toBe(true);
					expect(s.contentLen).toBeGreaterThan(0);
					expect(s.headBytes! + s.contentLen + POLY_LENGTH).toBe(s.packedLen);
				} else {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
				}
			});
			const newBytes = await getRandom(5*segSize);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 5*segSize + 100 },
					{ src: 'new', len: 5*segSize }
				]);
		});

		itAsync(`cutting, growing to original size, and cutting over new segment` , async () => {
			await writer.setContentLength(5*segSize + 100);
			await writer.setContentLength(10*segSize + 100);
			await writer.setContentLength(9*segSize);
			expect(writer.contentLength).toBe(9*segSize);
			const segs6 = Array.from(writer.segmentInfos());
			expect(segs6.length).toBe(9);
			segs6.forEach((s, i) => {
				if (i < 5) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
				} else if (i === 5) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.needPacking).toBe(true);
					expect(s.contentLen).toBeGreaterThan(0);
					expect(s.headBytes! + s.contentLen + POLY_LENGTH).toBe(s.packedLen);
				} else {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
				}
			});
			const newBytes = await getRandom(4*segSize - 100);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 5*segSize + 100 },
					{ src: 'new', len: 4*segSize - 100 }
				]);
		});

		itAsync(`changes file to endless with undefined length`, async () => {
			expect(typeof writer.contentLength).toBe('number');
			await writer.setContentLength(undefined);
			expect(writer.contentLength).toBeUndefined();
		});

	});

	describe(`.splice() changes layout of segments`, () => {

		let dataV1: Uint8Array;
		let objV1: ObjSource;
		let writer: SegmentsWriter;

		beforeEachAsync(async () => {
			({ objV1, dataV1 } = await prepObjV1(10, 100));
			writer = await makeSegmentsWriter(
				key, zerothHeaderNonce, 2,
				{ type: 'update', base: objV1 },
				getRandom, cryptor);
		});

		itAsync(`except for being a noop, when zero bytes removed, and zero bytes inserted`, async () => {
			await writer.splice(2*segSize+35, 0, 0);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(11);
			segs.forEach(s => {
				expect(s.type).toBe('base');
				expect(s.chain).toBe(0);
			});
		});

		itAsync(`by cutting out exactly one base segment`, async () => {
			const lenBeforeSplice = writer.contentLength!;
			await writer.splice(2*segSize, segSize, 0);
			expect(writer.contentLength).toBe(lenBeforeSplice - segSize);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(10);
			segs.forEach((s, i) => {
				expect(s.type).toBe('base');
				if (i < 2) {
					expect(s.chain).toBe(0);
				} else {
					expect(s.chain).toBe(1);
				}
			});
			const newBytes = new Uint8Array(0);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize },
					{ src: 'base', baseOfs: 3*segSize, len: 7*segSize + 100 }
				]);
		});

		itAsync(`by inserting new chain exactly between base segments`, async () => {
			const lenBeforeSplice = writer.contentLength!;
			await writer.splice(2*segSize, 0, segSize);
			expect(writer.contentLength).toBe(lenBeforeSplice + segSize);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(12);
			segs.forEach((s, i) => {
				if (i < 2) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 2) {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
					expect(s.contentLen).toBe(segSize);
				} else if (i < 11) {
					expect(s.chain).toBe(2);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 11) {
					expect(s.chain).toBe(2);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(100);
				}
			});
			const newBytes = await getRandom(segSize);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize },
					{ src: 'new', len: segSize },
					{ src: 'base', baseOfs: 2*segSize, len: 7*segSize + 100 }
				]);
		});
	
		itAsync(`by cutting out exactly one base segment and inserting new one between base chains`, async () => {
			await writer.splice(2*segSize, segSize, 0);
			const lenBeforeSplice = writer.contentLength!;
			await writer.splice(2*segSize, segSize, 200);
			expect(writer.contentLength).toBe(lenBeforeSplice - segSize + 200);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(10);
			segs.forEach((s, i) => {
				if (i < 2) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 2) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes).toBeUndefined();
					expect(s.contentLen).toBe(200);
				} else if (i < 9) {
					expect(s.chain).toBe(2);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 9) {
					expect(s.chain).toBe(2);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(100);
				}
			});
			const newBytes = await getRandom(200);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize },
					{ src: 'new', len: 200 },
					{ src: 'base', baseOfs: 4*segSize, len: 6*segSize + 100 }
				]);
		});

		itAsync(`by cutting out base segment in two chains and inserting new chain there`, async () => {
			await writer.splice(2*segSize, segSize, 0);
			const lenBeforeSplice = writer.contentLength!;
			await writer.splice(2*segSize-150, segSize, 200);
			expect(writer.contentLength).toBe(lenBeforeSplice - segSize + 200);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(11);
			const origSeg1 = dataV1.subarray(segSize, 2*segSize);
			const origSeg3 = dataV1.subarray(3*segSize, 4*segSize);
			segs.forEach((s, i) => {
				if (i === 0) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 1) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(segSize-150);
					expect(s.contentLen).toBe(150);
				} else if (i === 2) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes).toBeUndefined();
					expect(s.contentLen).toBe(50);
				} else if (i === 3) {
					expect(s.chain).toBe(2);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(150);
					expect(s.contentLen).toBe(0);
				} else if (i < 10) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 10) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(100);
				}
			});
			const newBytes = await getRandom(200);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize-150 },
					{ src: 'new', len: 200 },
					{ src: 'base', baseOfs: 4*segSize-150, len: 6*segSize + 250 }
				]);
		});

		itAsync(`by cutting out base segment in two chains and inserting new chain there, and cutting again in a new chain`, async () => {
			await writer.splice(2*segSize, segSize, 0);
			await writer.splice(2*segSize-150, segSize, 200);
			const lenBeforeSplice = writer.contentLength!;
			// The following splice, cuts base seg (i=1) by further 100, and cuts
			// new bytes by 50, besides further addition.
			await writer.splice(2*segSize-250, 150, segSize-150);
			expect(writer.contentLength).toBe(
				lenBeforeSplice - 150 + (segSize-150));
			const origSeg1 = dataV1.subarray(segSize, 2*segSize);
			const origSeg3 = dataV1.subarray(3*segSize, 4*segSize);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(11);
			segs.forEach((s, i) => {
				if (i === 0) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 1) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(segSize-250);
					expect(s.contentLen).toBe(250);
				} else if (i === 2) {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
					expect(s.contentLen).toBe(segSize-250);
				} else if (i === 3) {
					expect(s.chain).toBe(2);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(150);
					expect(s.contentLen).toBe(0);
				} else if (i < 10) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 10) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(100);
				}
			});
			const newBytes = await getRandom(segSize);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize-250 },
					{ src: 'new', len: segSize },
					{ src: 'base', baseOfs: 4*segSize-150, len: 6*segSize + 250 }
				]);
		});

		itAsync(`by inserting new chain in a middle of base chain segment`, async () => {
			const lenBeforeSplice = writer.contentLength!;
			await writer.splice(2*segSize-100, 0, segSize + 200);
			expect(writer.contentLength).toBe(lenBeforeSplice + segSize + 200);
			const origSeg1 = dataV1.subarray(segSize, 2*segSize);
			const segs = Array.from(writer.segmentInfos());
			expect(segs.length).toBe(14);
			segs.forEach((s, i) => {
				if (i === 0) {
					expect(s.chain).toBe(0);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 1) {
					expect(s.chain).toBe(1);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(segSize-100);
					expect(s.contentLen).toBe(100);
				} else if (i === 2) {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 3) {
					expect(s.chain).toBe(1);
					expect(s.type).toBe('new');
					expect(s.contentLen).toBe(100);
				} else if (i === 4) {
					expect(s.chain).toBe(2);
					if (s.type !== 'new') { throw new Error(`Expected new chain`); }
					expect(s.headBytes!).toBe(100);
					expect(s.contentLen).toBe(0);
				} else if (i < 13) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(segSize);
				} else if (i === 13) {
					expect(s.chain).toBe(3);
					expect(s.type).toBe('base');
					expect(s.contentLen).toBe(100);
				}
			});
			const newBytes = await getRandom(segSize + 200);
			await packAndCheckSplicedBytes(
				writer, key, zerothHeaderNonce, objV1, dataV1, newBytes, [
					{ src: 'base', baseOfs: 0, len: 2*segSize-100 },
					{ src: 'new', len: segSize + 200 },
					{ src: 'base', baseOfs: 2*segSize-100, len: 8*segSize + 200 }
				]);
		});

	});

	describe(`in restarted mode`, () => {

		itAsync(`can't change its geometry`, async () => {
			const version = 2;
			const newWriter = await makeSegmentsWriter(
				key, zerothHeaderNonce, version,
				{ type: 'new', segSize: 16 },
				getRandom, cryptor);
			await newWriter.setContentLength(6*1024*1024+3456);
			const header = await newWriter.packHeader();
	
			const restartedWriter = await makeSegmentsWriter(
				key, zerothHeaderNonce, version,
				{ type: 'restart', header },
				getRandom, cryptor);
	
			await restartedWriter.setContentLength(600)
			.then(
				() => fail(`setContentLength must fail in restarted mode`),
				() => {});
	
			await restartedWriter.splice(500, 0, 20)
			.then(
				() => fail(`splice must fail in restarted mode`),
				() => {});
	
		});
	
	});

	describe(`.segmentInfos()`, () => {

		let dataV1: Uint8Array;
		let objV1: ObjSource;
		let writer: SegmentsWriter;

		beforeEachAsync(async () => {
			({ objV1, dataV1 } = await prepObjV1(10, 100));
			writer = await makeSegmentsWriter(
				key, zerothHeaderNonce, 2,
				{ type: 'update', base: objV1 },
				getRandom, cryptor);
		});

		itAsync(`may iterate over all and part of segments`, async () => {
			const iterAll = writer.segmentInfos();
			const all = Array.from(iterAll);
			expect(all.length).toBe(11);
			const iterLastFour = writer.segmentInfos(all[all.length-4]);
			const lastFour = Array.from(iterLastFour);
			expect(lastFour.length).toBe(4);
			for (let i=0; i<4; i+=1) {
				const fromAll = all[all.length-4+i];
				const fromFour = lastFour[i];
				expect(fromAll.chain).toBe(fromFour.chain);
				expect(fromAll.seg).toBe(fromFour.seg);
			}
		});

	});

});

