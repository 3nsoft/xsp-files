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
import { makeSegmentsWriter, NONCE_LENGTH, KEY_LENGTH, makeSegmentsReader, ByteSink, ObjSource, LayoutNewSection, LayoutBaseSection, Layout } from '../../lib';
import { mockCryptor, getRandom, compare, objSrcFromArrays } from '../../test-lib/test-utils';
import { readSegsSequentially, packSegments } from '../../test-lib/segments-test-utils';
import { makeStreamSink, compareContent, packedBytesToSrc } from '../../test-lib/streams-test-utils';
import { assert } from '../../lib/utils/assert';
import { joinByteArrs } from '../../test-lib/buffer-utils';

const cryptor = mockCryptor();

type LayoutSection = LayoutBaseSection|LayoutNewSection;

function expectSection(
	l: Layout, sectionInd: number, src: LayoutSection['src'],
	ofs: number, len: number|undefined, baseOfs?: number
): void {
	if (typeof baseOfs === 'number') { assert(
		src === 'base', 'baseOfs should be present in check of base section'); }
	if (src === 'base') { assert(
		typeof baseOfs === 'number', 'check of base needs baseOfs'); }
	const section = l.sections[sectionInd];
	if (section) {
		expect(section.src).toBe(src, `wrong source in section ${sectionInd}`);
		expect(section.ofs).toBe(ofs, `wrong offset in section ${sectionInd}`);
		expect(section.len).toBe(len, `wrong length in section ${sectionInd}`);
		if (typeof baseOfs === 'number') { 
			expect((section as LayoutBaseSection).baseOfs).toBe(baseOfs, 'wrong base offset');
		} else {
			expect((section as LayoutBaseSection).baseOfs).toBeUndefined('expect no base offset');
		}
	} else {
		fail(`section index ${sectionInd} is not in layout with ${l.sections.length} sections`);
	}
}

async function checkAllNewBytesLayout(
	sink: ByteSink, expectedSize: number|undefined
): Promise<void> {
	const sizeInfo = await sink.getSize();
	if (expectedSize === undefined) {
		expect(sizeInfo.isEndless).toBeTruthy(`sink endless flag in endless sink`);
	} else {
		expect(sizeInfo.isEndless).toBeFalsy(`sink endless flag in finite sink`);
		expect(sizeInfo.size).toBe(expectedSize, `finite sink size`);
	}
	const layout = await sink.showLayout();
	expect(layout.sections.length).toBe(1, `number of sections in all new bytes layout`);
	expectSection(layout, 0, 'new', 0, expectedSize);
}

describe(`Encrypting byte sink (underlying version format 1)`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;
	const payloadFormat = 2;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	function makeSink(
		base?: ObjSource
	): Promise<{ byteSink: ByteSink;
			completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }> }> {
		return makeStreamSink(
			key, zerothNonce, version, payloadFormat, cryptor, base);
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

		const size = (await byteSink.getSize()).size;
		expect(size).toBe(content.length);
		const layout = await byteSink.showLayout();
		expect(layout.base).toBeUndefined();
		expect(Array.isArray(layout.sections)).toBeTruthy();
		if (size === 0) {
			expect(layout.sections.length).toBe(0);
		} else {
			expect(layout.sections.length).toBe(1);
			expectSection(layout, 0, 'new', 0, size);
		}

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

		await checkAllNewBytesLayout(byteSink, content.length);

		await compareContent(
			key, zerothNonce, version, completion, content, cryptor);
	});

	async function prepAsBase(content: Uint8Array): Promise<ObjSource> {
		const baseVersion = version - 1;
		const segWriter = await makeSegmentsWriter(
			key, zerothNonce, baseVersion,
			{ type: 'new', segSize: 16, payloadFormat },
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

		// do layout change, and write in big a chunk
		const { byteSink, completion } = await makeSink(baseSrc);

		// layout change
		await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

		// write out new bytes
		await byteSink.write(cut1.ofs, cut1.ins);
		await byteSink.done();

		const size = (await byteSink.getSize()).size;
		expect(size).toBe(expectedContent.length);
		const layout = await byteSink.showLayout();
		expect(layout.base).toBe(baseSrc.version);
		expect(layout.sections.length).toBe(3);
		expectSection(layout, 0, 'base', 0, cut1.ofs, 0);
		expectSection(layout, 1, 'new', cut1.ofs, cut1.ins.length);
		expectSection(layout, 2, 'base',
			cut1.ofs + cut1.ins.length, size - (cut1.ofs + cut1.ins.length),
			cut1.ofs + cut1.del);

		await compareContent(
			key, zerothNonce, version, completion, expectedContent, cryptor);
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


		// do layout change from start to end, and writing in big chunks
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

		await compareContent(
			key, zerothNonce, version, completion, expectedContent, cryptor);
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

		// do layout change, and write in big a chunk
		const { byteSink, completion } = await makeSink(baseSrc);

		// layout change
		await byteSink.spliceLayout(cut1.ofs, cut1.del, cut1.ins.length);

		// freeze layout
		await byteSink.freezeLayout();

		// write out new bytes
		await byteSink.write(cut1.ofs, cut1.ins);
		await byteSink.done();

		const size = (await byteSink.getSize()).size;
		expect(size).toBe(expectedContent.length);
		const layout = await byteSink.showLayout();
		expect(layout.sections.length).toBe(3);
		expectSection(layout, 0, 'base', 0, cut1.ofs, 0);
		expectSection(layout, 1, 'new', cut1.ofs, cut1.ins.length);
		expectSection(layout, 2, 'base',
			cut1.ofs + cut1.ins.length, size - (cut1.ofs + cut1.ins.length),
			cut1.ofs + cut1.del);

		await compareContent(
			key, zerothNonce, version, completion, expectedContent, cryptor);
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

		// do layout change from start to end, and writing in big chunks
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

		await compareContent(
			key, zerothNonce, version, completion, expectedContent, cryptor);
	});

	itAsync(`splices base like sink with attrs does`, async () => {
		const baseBytes = await getRandom(10000);
		const baseSrc = await prepAsBase(baseBytes);

		const { byteSink, completion } = await makeSink(baseSrc);

		let layout = await byteSink.showLayout();
		expect(layout.sections.length).toBe(1);
		expectSection(layout, 0, 'base', 0, 10000, 0);

		const initChunk = await getRandom(30);

		await byteSink.spliceLayout(0, 30, 30);
		await byteSink.write(0, initChunk.subarray(0, 5));

		layout = await byteSink.showLayout();
		expect(layout.sections.length).toBe(2);
		expectSection(layout, 0, 'new', 0, 30);
		expectSection(layout, 1, 'base', 30, 9970, 30);

		await byteSink.setSize(9100);

		layout = await byteSink.showLayout();
		expect(layout.sections.length).toBe(2);
		expectSection(layout, 0, 'new', 0, 30);
		expectSection(layout, 1, 'base', 30, 9070, 30);

		await byteSink.write(5, initChunk.subarray(5));
		await byteSink.done();

		const expectedContent = joinByteArrs([
			initChunk, baseBytes.subarray(30, 9100)
		]);
		await compareContent(
			key, zerothNonce, version, completion, expectedContent, cryptor);
	});

	itAsync(`supports file sink use pattern (scenario 1)`, async () => {

		const chunk1 = await getRandom(10000);
		const chunk2 = await getRandom(100);
		const tail1 = await getRandom(56);

		const { byteSink: s1, completion: c1 } = await makeSink();

		await s1.setSize(0);
		await s1.spliceLayout(0, 10000, 10000);
		await s1.write(0, chunk1);
		expect((await s1.getSize()).size).toBe(10000, 'content length');
		await s1.spliceLayout(10000, 100, 100);
		await s1.write(10000, chunk2);
		expect((await s1.getSize()).size).toBe(10100, 'content length');
		await s1.setSize(10156);
		await s1.write(10100, tail1);
		await s1.done();

		const expectedContent1 = joinByteArrs([ chunk1, chunk2, tail1 ]);
		await compareContent(
			key, zerothNonce, version, c1, expectedContent1, cryptor);

		const baseForS2 = await packedBytesToSrc(2, c1);
		const { byteSink: s2, completion: c2 } = await makeSink(baseForS2);

		const tail2 = await getRandom(72);

		expect((await s2.getSize()).size).toBe(10156, 'initial content length');
		await s2.setSize(10100);
		expect((await s2.getSize()).size).toBe(10100, 'content length after tail cut');
		await s2.spliceLayout(5000, 4000, 0);
		expect((await s2.getSize()).size).toBe(6100, 'content length after middle cut');

		let layout = await s2.showLayout();
		expect(layout.sections.length).toBe(2);
		expectSection(layout, 0, 'base', 0, 5000, 0);
		expectSection(layout, 1, 'base', 5000, 1100, 9000);
	
		await s2.setSize(6172);
		layout = await s2.showLayout();
		expect(layout.sections.length).toBe(3);
		expectSection(layout, 0, 'base', 0, 5000, 0);
		expectSection(layout, 1, 'base', 5000, 1100, 9000);
		expectSection(layout, 2, 'new', 6100, 72);

		await s2.write(6100, tail2);
		await s2.done();

		const expectedContent2 = joinByteArrs([
			chunk1.subarray(0, 5000), chunk1.subarray(9000), chunk2, tail2
		]);
		await compareContent(
			key, zerothNonce, version, c2, expectedContent2, cryptor);
	});

	itAsync(`removes base completely and writes new bytes`, async () => {
		const baseSrc = await prepAsBase(await getRandom(16));

		const { byteSink, completion } = await makeSink(baseSrc);
		let ofs = 0;
		await byteSink.setSize(ofs);

		const content = await getRandom(40);
		for (const chunk of [ content.slice(0, 20), content.slice(20) ]) {
			await byteSink.spliceLayout(ofs, 0, chunk.length);
			await byteSink.write(ofs, chunk);
			ofs += chunk.length;
		}
		await byteSink.done();

		await compareContent(
			key, zerothNonce, version, completion, content, cryptor);
	});

	itAsync(`removes base partially and writes new bytes`, async () => {
		const baseContent = await getRandom(16);
		const baseSrc = await prepAsBase(baseContent);

		const { byteSink, completion } = await makeSink(baseSrc);
		let ofs = 5;
		await byteSink.setSize(ofs);

		const content = await getRandom(60);
		content.slice(0, ofs).set(baseContent.slice(0, ofs));
		await byteSink.spliceLayout(ofs, 0, 40 - ofs);
		for (const chunk of [ content.slice(ofs, 20), content.slice(20, 40) ]) {
			await byteSink.write(ofs, chunk);
			ofs += chunk.length;
		}

		await byteSink.spliceLayout(ofs, 0, content.length - ofs);
		await byteSink.write(ofs, content.slice(ofs));

		await byteSink.done();

		await compareContent(
			key, zerothNonce, version, completion, content, cryptor);
	});

});
