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
import { makeSegmentsWriter, NONCE_LENGTH, KEY_LENGTH, makeSegmentsReader, ByteSink, ObjSource, ByteSinkWithAttrs } from '../../lib';
import { mockCryptor, getRandom, compare, objSrcFromArrays } from '../../test-lib/test-utils';
import { readSegsSequentially, packSegments } from '../../test-lib/segments-test-utils';
import { makeStreamSink, makeStreamSinkWithAttrs, compareContentAndAttrs, packAttrsAndConentAsObjSource } from '../../test-lib/streams-test-utils';

const cryptor = mockCryptor();

async function compareContent(
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }>,
	expectation: Uint8Array
): Promise<void> {
	const { header, allSegs } = await completion;
	const segReader = await makeSegmentsReader(
		key, zerothNonce, version, header, cryptor);
	const decrContent = await readSegsSequentially(segReader, allSegs);
	compare(decrContent, expectation);
}

describe(`Encrypting byte sink (underlying version format 1)`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	function makeSink(
		base?: ObjSource
	): Promise<{ byteSink: ByteSink;
			completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }> }> {
		return makeStreamSink(key, zerothNonce, version, cryptor, base);
	}

	async function testSequentialWriting(
		content: Uint8Array, setSizeUpfront: boolean, writeSize: number
	): Promise<void> {
		const { byteSink, completion } = await makeSink();
		if (setSizeUpfront) {
			await byteSink.setSize(content.length);
		}

		for (let pointer=0; pointer < content.length; pointer+=writeSize) {
			const chunkEnd = pointer + writeSize;
			await byteSink.write(pointer, content.subarray(pointer, chunkEnd));
		}
		await byteSink.done();
		expect((await byteSink.getSize()).size).toBe(content.length);

		const { header, allSegs } = await completion;

		// decrypt bytes and compare to original content
		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		const decrContent = await readSegsSequentially(segReader, allSegs);
		compare(decrContent, content);
	}

	itAsync(`encrypts bytes with an unknown a priori size`, async () => {
		// do test, reading in chunks of 250
		for (const len of [ 0, 2*1024, 4*1024, 4*1024+1, 4*1024+100, 9*1024 ]) {
			await testSequentialWriting(await getRandom(len), false, 250);
		}
		// do test, reading in chunks of 200K
		for (const len of [ 1024*1024 ]) {
			await testSequentialWriting(await getRandom(len), false, 200*1024);
		}
	});

	itAsync(`encrypts bytes with known a priori size`, async () => {
		// do test, reading in chunks of 250
		for (const len of [ 0, 2*1024, 4*1024, 4*1024+1, 4*1024+100, 9*1024 ]) {
			await testSequentialWriting(await getRandom(len), true, 250);
		}
		// do test, reading in chunks of 200K
		for (const len of [ 1024*1024 ]) {
			await testSequentialWriting(await getRandom(len), true, 200*1024);
		}
	});

	itAsync(`encrypts bytes written out of order`, async () => {
		const { byteSink, completion } = await makeSink();
		const content = await getRandom((4*4 + 2)*1024);
		const cutPos = (4*4)*1024-200;
		const c1 = content.subarray(0, cutPos);
		const c2 = content.subarray(cutPos);

		// write last chunk first, and second chunk later
		await byteSink.write(cutPos, c2);
		await byteSink.setSize(content.length);
		await byteSink.write(0, c1);
		await byteSink.done();

		await compareContent(key, zerothNonce, version, completion, content);
	});

	async function prepAsBase(content: Uint8Array): Promise<ObjSource> {
		const baseVersion = version - 1;
		const segWriter = await makeSegmentsWriter(
			key, zerothNonce, baseVersion,
			{ type: 'new', segSize: 16 },
			getRandom, cryptor);
		const segs = await packSegments(segWriter, content);
		const header = await segWriter.packHeader();
		return objSrcFromArrays(baseVersion, header, segs);
	}

	itAsync(`splices base version and writes new bytes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const baseSrc = await prepAsBase(baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(cut1.ofs + cut1.del),
			cut1.ofs + cut1.ins.length);

		{ // do layout change, and write in big a chunk
			const { byteSink, completion } = await makeSink(baseSrc);

			// layout change
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

			// write out new bytes
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContent(key, zerothNonce, version, completion, expectedContent);
		}
	});

	itAsync(`splices base in few places and writes new bytes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const baseSrc = await prepAsBase(baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const cut2 = { ofs: 10000, del: 250, ins: await getRandom(250) };
		const tailAddition = await getRandom(500);
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length - cut2.del
			+ cut2.ins.length
			+ tailAddition.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(
				cut1.ofs + cut1.del,
				cut1.del + cut2.ofs + cut1.ins.length),
			cut1.ofs + cut1.ins.length);
		expectedContent.set(cut2.ins, cut2.ofs);
		expectedContent.set(
			baseContent.slice(cut1.del - cut1.ins.length + cut2.ofs + cut2.del),
			cut2.ofs + cut2.ins.length);
		expectedContent.set(
			tailAddition,
			expectedContent.length - tailAddition.length);


		{ // do layout change from start to end, and writing in big chunks
			const { byteSink, completion } = await makeSink(baseSrc);
			// changing layout:
			// cut1
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);
			// cut2
			await byteSink.spliceLayout(cut2.ofs, cut2.del, cut2.ins.length);
			// adding tail
			const sinkSize = await byteSink.getSize();
			expect(sinkSize.isEndless).toBe(false);
			const lenAfterCuts = sinkSize.size;
			await byteSink.setSize(lenAfterCuts + tailAddition.length);

			// writing bytes
			await byteSink.write(lenAfterCuts, tailAddition);
			await byteSink.write(cut2.ofs, cut2.ins);
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContent(key, zerothNonce, version, completion, expectedContent);
		}
	});

	itAsync(`splices base version, freezes layout and writes new bytes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const baseSrc = await prepAsBase(baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(cut1.ofs + cut1.del),
			cut1.ofs + cut1.ins.length);

		{ // do layout change, and write in big a chunk
			const { byteSink, completion } = await makeSink(baseSrc);

			// layout change
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

			// freeze layout
			await byteSink.freezeLayout();

			// write out new bytes
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContent(key, zerothNonce, version, completion, expectedContent);
		}
	});

	itAsync(`splices base in few places, freezes layout and writes new bytes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const baseSrc = await prepAsBase(baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const cut2 = { ofs: 10000, del: 250, ins: await getRandom(250) };
		const tailAddition = await getRandom(500);
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length - cut2.del
			+ cut2.ins.length
			+ tailAddition.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(
				cut1.ofs + cut1.del,
				cut1.del + cut2.ofs + cut1.ins.length),
			cut1.ofs + cut1.ins.length);
		expectedContent.set(cut2.ins, cut2.ofs);
		expectedContent.set(
			baseContent.slice(cut1.del - cut1.ins.length + cut2.ofs + cut2.del),
			cut2.ofs + cut2.ins.length);
		expectedContent.set(
			tailAddition,
			expectedContent.length - tailAddition.length);


		{ // do layout change from start to end, and writing in big chunks
			const { byteSink, completion } = await makeSink(baseSrc);

			// changing layout:
			// cut1
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);
			// cut2
			await byteSink.spliceLayout(cut2.ofs, cut2.del, cut2.ins.length);
			// adding tail
			const sinkSize = await byteSink.getSize();
			expect(sinkSize.isEndless).toBe(false);
			const lenAfterCuts = sinkSize.size;
			await byteSink.setSize(lenAfterCuts + tailAddition.length);

			// freeze layout
			await byteSink.freezeLayout();

			// writing bytes
			await byteSink.write(lenAfterCuts, tailAddition);
			await byteSink.write(cut2.ofs, cut2.ins);
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContent(key, zerothNonce, version, completion, expectedContent);
		}
	});

});

describe(`Encrypting byte sink with attributes (underlying version format 2)`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	function makeSink(
		base?: ObjSource, baseAttrSize?: number
	): Promise<{ byteSink: ByteSinkWithAttrs;
			completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }> }> {
		return makeStreamSinkWithAttrs(
			key, zerothNonce, version, cryptor,
			(base ? { src: base, attrSize: baseAttrSize! } : undefined));
	}

	itAsync(`writes attributes before writing content`, async () => {
		const { byteSink, completion } = await makeSink();
		const content = await getRandom((4*4 + 2)*1024);
		const attrs = await getRandom(25);
		const cutPos = (4*4)*1024-200;
		const c1 = content.subarray(0, cutPos);
		const c2 = content.subarray(cutPos);

		await byteSink.writeAttrs(attrs);

		// write last chunk first, and second chunk later
		await byteSink.write(cutPos, c2);
		await byteSink.setSize(content.length);
		await byteSink.write(0, c1);
		await byteSink.done();

		await compareContentAndAttrs(
			key, zerothNonce, version, completion, content, attrs, cryptor);
	});

	itAsync(`sets attributes before writing content`, async () => {
		const { byteSink, completion } = await makeSink();
		const content = await getRandom((4*4 + 2)*1024);
		const attrs = await getRandom(25);
		const cutPos = (4*4)*1024-200;
		const c1 = content.subarray(0, cutPos);
		const c2 = content.subarray(cutPos);

		await byteSink.setAttrSectionSize(attrs.length);

		// write last chunk first, attributes and second chunk later
		await byteSink.write(cutPos, c2);
		await byteSink.setSize(content.length);
		await byteSink.writeAttrs(attrs);
		await byteSink.write(0, c1);
		await byteSink.done();

		await compareContentAndAttrs(
			key, zerothNonce, version, completion, content, attrs, cryptor);
	});

	function prepAsBase(
		attrs: Uint8Array, content: Uint8Array
	): Promise<ObjSource> {
		const baseVersion = version - 1;
		return packAttrsAndConentAsObjSource(
			attrs, content, key, zerothNonce, baseVersion, cryptor);
	}

	itAsync(`splices base without changing attributes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const initAttrs = await getRandom(25);
		const baseSrc = await prepAsBase(initAttrs, baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(cut1.ofs + cut1.del),
			cut1.ofs + cut1.ins.length);

		{ // do layout change, and write in big a chunk
			const { byteSink, completion } = await makeSink(baseSrc, initAttrs.length);

			// layout change
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

			// write out new bytes
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContentAndAttrs(
				key, zerothNonce, version, completion, expectedContent, initAttrs,cryptor);
		}
	});

	itAsync(`changes attributes then splices base`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const initAttrs = await getRandom(25);
		const baseSrc = await prepAsBase(initAttrs, baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(cut1.ofs + cut1.del),
			cut1.ofs + cut1.ins.length);
		const attrs = await getRandom(10);

		{ // do layout change, and write in big a chunk
			const { byteSink, completion } = await makeSink(baseSrc, initAttrs.length);

			await byteSink.writeAttrs(attrs);

			// layout change
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

			// write out new bytes
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContentAndAttrs(
				key, zerothNonce, version, completion, expectedContent, attrs,
				cryptor);
		}
	});

	itAsync(`splices base then changes attributes`, async () => {
		const baseContent = await getRandom((10*4)*1024 + 2000);
		const initAttrs = await getRandom(25);
		const baseSrc = await prepAsBase(initAttrs, baseContent);
		const cut1 = { ofs: 3000, del: 5*4*1024, ins: await getRandom(250) };
		const expectedContent = new Uint8Array(
			baseContent.length
			- cut1.del + cut1.ins.length);
		expectedContent.set(baseContent.slice(0, cut1.ofs), 0);
		expectedContent.set(cut1.ins, cut1.ofs);
		expectedContent.set(
			baseContent.slice(cut1.ofs + cut1.del),
			cut1.ofs + cut1.ins.length);
		const attrs = await getRandom(10);

		{ // do layout change, and write in big a chunk
			const { byteSink, completion } = await makeSink(baseSrc, initAttrs.length);

			// layout change
			await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

			await byteSink.setAttrSectionSize(attrs.length);

			// write out new bytes
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.writeAttrs(attrs);
			await byteSink.done();

			await compareContentAndAttrs(
				key, zerothNonce, version, completion, expectedContent, attrs,
				cryptor);
		}
	});

});
