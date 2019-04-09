/*
 Copyright (C) 2016 - 2019 3NSoft Inc.
 
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
import { makeSegmentsWriter, NONCE_LENGTH, KEY_LENGTH, makeSegmentsReader, ByteSink, Layout, ObjSource, makeEncryptingByteSink, EncrEvent, SegEncrEvent } from '../../lib';
import { mockCryptor, getRandom, compare, objSrcFromArrays } from '../../test-lib/test-utils';
import { Observable, Observer } from 'rxjs';
import { share, tap } from 'rxjs/operators';
import { readSegsSequentially, packSegments } from '../segments/xsp';
import { assert } from '../../lib/utils/assert';

const cryptor = mockCryptor();

describe(`Encrypting byte writer, created by makeEncryptingByteWriter`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	const version = 3;

	beforeEachAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
	});

	async function makeSink(base?: ObjSource):
			Promise<{ byteSink: ByteSink;
						completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }> }> {
		const segWriter = await makeSegmentsWriter(
			key, zerothNonce, (base ? base.version + 1 : version),
			(base ? { type: 'update', base } : { type: 'new', segSize: 16 }),
			getRandom, cryptor);
		const { sink, sub } = await makeEncryptingByteSink(segWriter);
		const enc$ = Observable.create((obs: Observer<EncrEvent>) => sub(obs))
		.pipe(share());
		const completion = startProcessingWriteEvents(enc$, base);
		return { byteSink: sink, completion };
	}

	function startProcessingWriteEvents(enc$: Observable<EncrEvent>,
			base: ObjSource|undefined):
			Promise<{ header: Uint8Array; allSegs: Uint8Array; }> {
		let header: Uint8Array;
		let layout: Layout;
		let segs: SegEncrEvent[] = [];
		return enc$.pipe(
			tap(ev => {
				if (ev.type === 'header') {
					header = ev.header;
					layout = ev.layout;
				} else if (ev.type === 'seg') {
					segs.push(ev);
				} else {
					throw new Error(`Unknown encryption event type`);
				}
			})
		).toPromise()
		.then(async () => {
			if (layout.sections.length === 0) {
				if (segs.length !== 0) { throw new Error(
					`Layout has zero length, while there are new segments`); }
				return { header, allSegs: new Uint8Array(0) };
			}

			segs.sort((a, b) => {
				const aStart = a.segInfo.packedOfs;
				const aEnd = aStart + a.segInfo.packedLen;
				const bStart = b.segInfo.packedOfs;
				const bEnd = bStart + b.segInfo.packedLen;
				if (aEnd <= bStart) { return -1; }
				if (bEnd <= aStart) { return 1; }
				throw new Error(`Have an overlapping segments`);
			});

			// we'll use layout to find total packed length that may include base
			// sections, this allows to perform checks of layout array object
			let totalLen = ((layout.sections.length === 0) ?
				0 : layout.sections[layout.sections.length-1].ofs);
			for (let i=0; i<layout.sections.length; i+=1) {
				const chunk = layout.sections[i];
				if (chunk.src === 'new') {
					if (chunk.len === undefined) {
						if ((i+1) < layout.sections.length) { throw new Error(
							`Layout chunk with undefined length is not the last chunk in the layout`); }
						const lastNewSeg = segs[segs.length-1];
						totalLen = lastNewSeg.segInfo.packedOfs + lastNewSeg.segInfo.packedLen;
					} else {
						assert(chunk.len > 0);
						totalLen += chunk.len;
					}
				} else if (chunk.src === 'base') {
					if (!base) { throw new Error(
						`Layout has base section, while there is no base given`); }
					assert(chunk.len > 0);
					totalLen += chunk.len;
				} else {
					throw new Error(`Unknown value of src field in layout info`);
				}
			}

			const allSegs = new Uint8Array(totalLen);

			// write new segments
			for (const s of segs) {
				allSegs.set(s.seg, s.segInfo.packedOfs);
			}

			// add base bytes, if there are any
			if (base) {
				for (const chunk of layout.sections) {
					if (chunk.src !== 'base') { continue; }
					await base.segSrc.seek(chunk.baseOfs);
					const baseChunk = await base.segSrc.read(chunk.len);
					if (!baseChunk
					|| (baseChunk.length !== chunk.len)) { throw new Error(
						`Not enough base segment bytes`); }
					allSegs.set(baseChunk, chunk.ofs);
				}
			}

			return { header, allSegs };
		});
	}

	async function testSequentialWriting(content: Uint8Array,
			setSizeUpfront: boolean, writeSize: number): Promise<void> {
		const { byteSink, completion } = await makeSink();
		if (setSizeUpfront) {
			await byteSink.setSize(content.length);
		}
		
		for (let pointer=0; pointer < content.length; pointer+=writeSize) {
			const chunkEnd = pointer + writeSize;
			await byteSink.write(pointer, content.subarray(pointer, chunkEnd));
		}
		await byteSink.done();
		expect(await byteSink.getSize()).toBe(content.length);

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

	async function compareContentAt(
			completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }>,
			expectation: Uint8Array): Promise<void> {
		const { header, allSegs } = await completion;
		const segReader = await makeSegmentsReader(
			key, zerothNonce, version, header, cryptor);
		const decrContent = await readSegsSequentially(segReader, allSegs);
		compare(decrContent, expectation);
	}

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

		await compareContentAt(completion, content);
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

			await compareContentAt(completion, expectedContent);
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
			const lenAfterCuts = (await byteSink.getSize())!;
			await byteSink.setSize(lenAfterCuts + tailAddition.length);

			// writing bytes
			await byteSink.write(lenAfterCuts, tailAddition);
			await byteSink.write(cut2.ofs, cut2.ins);
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContentAt(completion, expectedContent);
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

			await compareContentAt(completion, expectedContent);
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
			const lenAfterCuts = (await byteSink.getSize())!;
			await byteSink.setSize(lenAfterCuts + tailAddition.length);

			// freeze layout
			await byteSink.freezeLayout();

			// writing bytes
			await byteSink.write(lenAfterCuts, tailAddition);
			await byteSink.write(cut2.ofs, cut2.ins);
			await byteSink.write(cut1.ofs, cut1.ins);
			await byteSink.done();

			await compareContentAt(completion, expectedContent);
		}
	});

});
