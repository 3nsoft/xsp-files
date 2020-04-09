/*
 Copyright (C) 2018 - 2020 3NSoft Inc.
 
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

import { ByteSink, Observer, Layout, ByteSinkWithAttrs, ByteSourceWithAttrs } from './common';
import { SegmentsWriter, writeExc, NewSegmentInfo } from '../segments/writer';
import { LocationInSegment, SegId, storeUintIn4Bytes } from '../segments/xsp-info';
import { assert } from '../utils/assert';
import { SingleProc, makeSyncedFunc } from '../utils/process-syncing';

class EncryptingByteSink implements ByteSink {

	private encOutput: Observer<EncrEvent>|undefined = undefined;
	private backpressure: (() => Promise<void>)|undefined = undefined;
	private isCompleted = false;
	private buffer = new ChunksBuffer();
	private biggestContentOfs = 0;
	private reencryptSegs: UnpackedSegsForReencryption|undefined = undefined;

	constructor(
		private segWriter: SegmentsWriter
	) {
		this.reencryptSegs = (this.segWriter.hasBase ?
			new UnpackedSegsForReencryption(
				this.segWriter.unpackedReencryptChainSegs.bind(this.segWriter),
				this.packAndOutSeg.bind(this)) :
			undefined);
		Object.seal(this);
	}

	static makeFor(
		segWriter: SegmentsWriter
	): { sink: ByteSink; sub: Subscribe; } {
		const encWriter = new EncryptingByteSink(segWriter);
		const syncProc = new SingleProc();
		const sink: ByteSink = {
			getSize: makeSyncedFunc(syncProc, encWriter, encWriter.getSize),
			setSize: makeSyncedFunc(syncProc, encWriter, encWriter.setSize),
			showLayout: makeSyncedFunc(syncProc, encWriter, encWriter.showLayout),
			spliceLayout: makeSyncedFunc(
				syncProc, encWriter, encWriter.spliceLayout),
			freezeLayout: makeSyncedFunc(
				syncProc, encWriter, encWriter.freezeLayout),
			write: makeSyncedFunc(syncProc, encWriter, encWriter.write),
			done: makeSyncedFunc(syncProc, encWriter, encWriter.done)
		};
		const sub = encWriter.start.bind(encWriter);
		return { sink, sub };
	}

	private start(
		obs: Observer<EncrEvent>, backpressure?: () => Promise<void>
	): (() => void) {
		if (this.encOutput) { throw new Error(`This sink is already subsribed`); }
		if (!obs.next || !obs.error || !obs.complete) { throw new Error(
			`Given output observer must have all methods for use here`); }
		this.encOutput = obs;
		if (typeof backpressure === 'function') {
			this.backpressure = backpressure;
		}
		return this.stop.bind(this);
	}

	private stop(): void {
		this.isCompleted = true;
		this.encOutput = undefined as any;
	}

	async showLayout(): Promise<Layout> {
		return this.segWriter.showContentLayout();
	}

	async spliceLayout(pos: number, del: number, ins: number): Promise<void> {
		if (this.segWriter.isHeaderPacked) { throw new Error(
			`Layout is already frozen`); }
		assert(Number.isInteger(pos) && (pos >= 0)
			&& Number.isInteger(del) && (del >= 0)
			&& Number.isInteger(ins) && (ins >= 0), `Invalid parameters given`);
		if (del > 0) {
			this.buffer.ensureNoOverlap(pos, pos+del);
		}
		await this.segWriter.splice(pos, del, ins);
		this.buffer.changePositionsOnSplicing(pos, del, ins);
	}

	async freezeLayout(): Promise<void> {
		if (this.segWriter.isHeaderPacked) { return; }
		if (!this.encOutput) { throw new Error(`This sink is not subsribed to`); }
		const header = await this.segWriter.packHeader();
		if (this.backpressure) {
			await this.backpressure();
		}
		const ev: HeaderEncrEvent = {
			type: 'header',
			header,
			layout: this.segWriter.showPackedLayout()
		};
		this.encOutput.next!(ev);

		if (this.reencryptSegs) {
			this.reencryptSegs.onLayoutFreeze();
		}

	}

	async done(err?: any): Promise<void> {
		if (!this.encOutput) { throw new Error(`This sink is not subsribed to`); }
		if (this.isCompleted) { return; }
		if (err) {
			this.isCompleted = true;
			this.encOutput.error!(err);
			this.stop();
			return;
		}

		await this.packTailFromBufferIfEndless();

		if (!this.segWriter.areSegmentsPacked) {
			if (this.reencryptSegs) {
				await this.reencryptSegs.packAll();
			}

			if (!this.segWriter.areSegmentsPacked) {
				err = new Error(
					`Completion fails, cause not all bytes were written`);
				await this.done(err);
				throw err;
			}
		}

		if (!this.segWriter.isHeaderPacked) {
			await this.freezeLayout();
		}
		this.encOutput.complete!();
	}

	async write(pos: number, bytes: Uint8Array): Promise<void> {
		if (!this.encOutput) { throw new Error(`This sink is not subsribed to`); }
		if (this.isCompleted) { throw new Error(`Writer is already done.`); }

		if (bytes.length === 0) { return; }

		try {
			this.buffer.ensureNoOverlap(pos, pos+bytes.length);

			const foundPos = this.segWriter.locateContentOfs(pos);

			const wholeSections = this.getWholeSegsAndBufferRest(foundPos, bytes);

			if (this.reencryptSegs && (wholeSections.length > 0)) {
				await this.reencryptSegs.packBeforeSeg(wholeSections[0][0]);
			}
			for (let s of wholeSections) {
				await this.packAndOutSeg(s[0], s[1]);
			}
		} catch (err) {
			await this.done(err);
			throw err;
		}

		const endOfs = pos + bytes.length;
		if (this.biggestContentOfs < endOfs) {
			this.biggestContentOfs = endOfs;
		}
	}

	private async packAndOutSeg(
		segInfo: NewSegmentInfo, content: Uint8Array
	): Promise<void> {
		const seg = await this.segWriter.packSeg(content, segInfo);
		if (this.backpressure) {
			await this.backpressure();
		}
		this.encOutput!.next!({ type: 'seg', seg, segInfo });
	}

	private async packTailFromBufferIfEndless(): Promise<void> {
		if (!this.segWriter.isEndlessFile) { return; }

		const tailChunk = this.buffer.extractTail();
		if (!tailChunk) {
			if (!this.segWriter.isHeaderPacked) {
				await this.setSize(this.biggestContentOfs);
			}
			return;
		}

		const pos = this.segWriter.locateContentOfs(tailChunk.start);
		if (pos.posInSeg !== 0) { throw new Error(
			`There are missing bytes`); }
		const segInfo = this.segWriter.segmentInfo(pos);
		if (segInfo.type !== 'new') { throw new Error(
			`Unexpected not-new segment`); }
		await this.packAndOutSeg(segInfo, tailChunk.bytes);
	}

	private getWholeSegsAndBufferRest(pos: LocationInSegment, bytes: Uint8Array):
			[ NewSegmentInfo, Uint8Array ][] {
		const wholeSegs: [ NewSegmentInfo, Uint8Array ][] = [];
		const segs = this.segWriter.segmentInfos(pos);

		// first segment
		{
			const { value: fstSeg } = segs.next();

			if (fstSeg.type === 'base') { throw writeExc('segsPacked',
				`Given bytes overlap base bytes`); }
			if (!fstSeg.needPacking) { throw writeExc('segsPacked'); }
			const posOfsInSeg = ((fstSeg.headBytes === undefined) ?
				pos.posInSeg : (pos.posInSeg - fstSeg.headBytes));
			if (posOfsInSeg < 0) { throw writeExc('segsPacked',
				`Given bytes overlap base bytes`); }

			if (posOfsInSeg === 0) {
				if (bytes.length < fstSeg.contentLen) {
					const tailBytes = this.buffer.findAndExtract(
						fstSeg.contentOfs+bytes.length,
						fstSeg.contentOfs+fstSeg.contentLen);
					if (!tailBytes) {
						this.buffer.add(fstSeg.contentOfs, bytes);
						return wholeSegs;
					}
					const wholeSeg = new Uint8Array(fstSeg.contentLen);
					wholeSeg.set(bytes);
					wholeSeg.set(tailBytes, bytes.length);
					wholeSegs.push([ fstSeg, wholeSeg ]);
					return wholeSegs;
				}

				const wholeSeg = bytes.subarray(0, fstSeg.contentLen);
				bytes = bytes.subarray(wholeSeg.length);
				wholeSegs.push([ fstSeg, wholeSeg ]);
			} else {
				const headChunk = this.buffer.findChunkWith(
					fstSeg.contentOfs, fstSeg.contentOfs+posOfsInSeg);

				if ((posOfsInSeg + bytes.length) < fstSeg.contentLen) {
					const tailChunk = this.buffer.findChunkWith(
						fstSeg.contentOfs+posOfsInSeg+bytes.length,
						fstSeg.contentOfs+posOfsInSeg+fstSeg.contentLen);
					if (!headChunk || !tailChunk) {
						this.buffer.add(fstSeg.contentOfs+posOfsInSeg, bytes);
						return wholeSegs;
					}
					const wholeSeg = new Uint8Array(fstSeg.contentLen);
					const headBytes = this.buffer.extractBytesFrom(headChunk,
						fstSeg.contentOfs, fstSeg.contentOfs+posOfsInSeg);
					wholeSeg.set(headBytes);
					wholeSeg.set(bytes, posOfsInSeg);
					const tailBytes = this.buffer.extractBytesFrom(tailChunk,
						fstSeg.contentOfs+posOfsInSeg+bytes.length,
						fstSeg.contentOfs+posOfsInSeg+fstSeg.contentLen);
					wholeSeg.set(tailBytes, posOfsInSeg+bytes.length);
					wholeSegs.push([ fstSeg, wholeSeg ]);
					return wholeSegs;
				}

				const oddFstChunk = bytes.subarray(
					0, fstSeg.contentLen-posOfsInSeg);
				bytes = bytes.subarray(oddFstChunk.length);
				if (headChunk) {
					const wholeSeg = new Uint8Array(fstSeg.contentLen);
					const headBytes = this.buffer.extractBytesFrom(headChunk,
						fstSeg.contentOfs, fstSeg.contentOfs+posOfsInSeg);
					wholeSeg.set(headBytes);
					wholeSeg.set(oddFstChunk, posOfsInSeg);
					wholeSegs.push([ fstSeg, wholeSeg ]);
				} else {
					this.buffer.add(fstSeg.contentOfs+posOfsInSeg, oddFstChunk);
				}
			}
		}

		// other segments
		while (bytes.length > 0) {
			const { done, value: seg } = segs.next();
			if (done) { throw writeExc('argsOutOfBounds',
				`Given bytes extend over file's end`); }

			if ((seg.type === 'base')
			|| (seg.headBytes !== undefined)) { throw writeExc('segsPacked',
				`Given bytes overlap base bytes`); }
			if (!seg.needPacking) {
				throw writeExc('segsPacked'); }

			if (bytes.length < seg.contentLen) {
				const tailBytes = this.buffer.findAndExtract(
					seg.contentOfs+bytes.length,
					seg.contentOfs+seg.contentLen);
				if (!tailBytes) {
					this.buffer.add(seg.contentOfs, bytes);
					return wholeSegs;
				}
				const wholeSeg = new Uint8Array(seg.contentLen);
				wholeSeg.set(bytes);
				wholeSeg.set(tailBytes, bytes.length);
				wholeSegs.push([ seg, wholeSeg ]);
				return wholeSegs;
			}
	
			const wholeSeg = bytes.subarray(0, seg.contentLen);
			bytes = bytes.subarray(wholeSeg.length);
			wholeSegs.push([ seg, wholeSeg ]);
		}

		return wholeSegs;
	}
	
	async setSize(size: number|undefined): Promise<void> {
		const tailChunk = ((size === undefined) ?
			undefined : this.buffer.extractTailIfEndsAt(size));

		await this.segWriter.setContentLength(size);

		if (!tailChunk) { return; }

		const pos = this.segWriter.locateContentOfs(tailChunk.start);
		let segInfo = this.segWriter.segmentInfo(pos);
		if (segInfo.type !== 'new') { throw new Error(
			`Unexpected not-new segment`); }
		let segEnd = segInfo.contentOfs + segInfo.contentLen;

		// tail chunk is inside of the last segment
		if (segEnd === size) {
			if (pos.posInSeg !== 0) {
				this.buffer.add(tailChunk.start, tailChunk.bytes);
			} else {
				await this.packAndOutSeg(segInfo, tailChunk.bytes);
			}
			return;
		}

		// tail chunk spans two last segments, and only last one is in chunk bytes
		const lastSeg = this.getNextSeg(pos);
		if (lastSeg.type !== 'new') { throw new Error(
			`Unexpected not-new segment`); }
		const bytesToBuffer = tailChunk.bytes.subarray(
			0, tailChunk.bytes.length - lastSeg.contentLen);
		const lastSegBytes = tailChunk.bytes.subarray(bytesToBuffer.length);
		this.buffer.add(tailChunk.start, bytesToBuffer);
		await this.packAndOutSeg(lastSeg, lastSegBytes);
	}

	private getNextSeg(seg: SegId) {
		const iter = this.segWriter.segmentInfos(seg);
		iter.next(); // should be this seg
		const { done, value: nextSeg } = iter.next();
		if (done) { throw new Error(`Unexpected end of segment's sequence`); }
		return nextSeg;
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		return {
			isEndless: this.segWriter.isEndlessFile,
			size: this.segWriter.contentFiniteLength
		};
	}

}
Object.freeze(EncryptingByteSink.prototype);
Object.freeze(EncryptingByteSink);

const EMPTY_ARR = new Uint8Array(0);

class UnpackedSegsForReencryption {

	private frozenSegs: NewSegmentInfo[]|undefined = undefined;

	constructor(
		private getSegs: SegmentsWriter['unpackedReencryptChainSegs'],
		private packSegs: EncryptingByteSink['packAndOutSeg']
	) {
		Object.seal(this);
	}

	async packAll(): Promise<void> {
		let segs: NewSegmentInfo[];
		if (this.frozenSegs) {
			segs = this.frozenSegs;
			this.frozenSegs = [];
		} else {
			segs = this.getSegs();
		}
		for (const segInfo of segs) {
			await this.packSegs(segInfo, EMPTY_ARR);
		}
	}

	onLayoutFreeze(): void {
		this.frozenSegs = this.getSegs();
	}

	async packBeforeSeg(segInfo: NewSegmentInfo): Promise<void> {
		if ((segInfo.seg !== 0) || (segInfo.chain === 0)) { return; }
		const segs = this.getSegs();
		if (!segs) { return; }
		const segsToPack: NewSegmentInfo[] = [];
		let possibleReencryptChain = segInfo.chain - 1;
		for (let i=segs.length-1; i<0; i-=1) {
			const segInfo = segs[i];
			if (segInfo.chain === possibleReencryptChain) {
				segsToPack.push(segInfo);
				possibleReencryptChain -= 1;
			} else if (segInfo.chain < possibleReencryptChain) {
				break;
			}
		}
		for (const s of segsToPack) {
			await this.packSegs(s, EMPTY_ARR);
		}
	}

}
Object.freeze(UnpackedSegsForReencryption.prototype);
Object.freeze(UnpackedSegsForReencryption);

interface Chunk {
	bytes: Uint8Array;
	start: number;
	end: number;
}

class ChunksBuffer {

	private chunks: Chunk[] = [];

	constructor() {
		Object.seal(this);
	}

	ensureNoOverlap(start: number, end: number): void {
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			if (start >= chunk.end) { continue; }
			if (end <= chunk.start) { return; }
			throw writeExc('segsPacked',
				`Given bytes overlap already buffered bytes`);
		}
	}

	changePositionsOnSplicing(pos: number, del: number, ins: number): void {
		const changeStart = pos - del;
		const delta = ins - del;
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			if (chunk.end < changeStart) { continue; }
			chunk.start += delta;
			chunk.end += delta;
		}
	}

	add(start: number, bytes: Uint8Array): void {
		const end = start + bytes.length;
		
		for (let i=0; i<this.chunks.length; i+=1) {
			const existing = this.chunks[i];
			if (existing.end < start) { continue; }
			if (existing.end === start) {
				const joinedBytes = new Uint8Array(
					existing.bytes.length+bytes.length);
				joinedBytes.set(existing.bytes);
				joinedBytes.set(bytes, existing.bytes.length);
				existing.bytes = joinedBytes;
				existing.end = end;
				return;
			}
			if (end === existing.start) {
				const joinedBytes = new Uint8Array(
					bytes.length+existing.bytes.length);
				joinedBytes.set(bytes);
				joinedBytes.set(existing.bytes, bytes.length);
				existing.bytes = joinedBytes;
				existing.start = start;
				return;
			}
			assert(end < existing.start,
				`Overlap of new bytes with already buffered ones`);
			// Note that below we copy bytes into new array. This is done to
			// detouch from any incoming buffers that may be shared/reused
			// elsewhere, wracking havoc here.
			const newChunk: Chunk = { start, end, bytes: new Uint8Array(bytes) };
			this.chunks.splice(i, 0, newChunk);
			return;
		}

		// We copy bytes here for the same reason as above.
		const newChunk: Chunk = { start, end, bytes: new Uint8Array(bytes) };
		this.chunks.push(newChunk);
	}

	extractBytesFrom(
		chunk: Chunk|number, start: number, end: number
	): Uint8Array {
		if (!(start < end)) { throw new Error(
			`Invalid extraction boundaries: start = ${start}, end = ${end}`); }

		let chunkInd: number;
		if (typeof chunk === 'number') {
			chunkInd = chunk;
			chunk = this.chunks[chunkInd];
			if (!chunk) { throw new Error(`Unknown chunk index ${chunkInd}`); }
		} else {
			chunkInd = this.chunks.indexOf(chunk);
			if (chunkInd < 0) { throw new Error(`Unknown chunk given`); }
		}

		const startOfs = start - chunk.start;
		const endOfs = chunk.end - end;

		if ((startOfs < 0) || (endOfs < 0)) { throw new Error(
			`Given boundaries go outside of a given chunk`); }

		if (startOfs === 0) {
			if (endOfs === 0) {
				this.chunks.splice(chunkInd, 1);
				return chunk.bytes;
			} else {
				const cutInd = chunk.bytes.length - endOfs;
				const extract = chunk.bytes.subarray(0, cutInd);
				chunk.bytes = chunk.bytes.subarray(cutInd);
				return extract;
			}
		} else {
			if (endOfs === 0) {
				const extract = chunk.bytes.subarray(startOfs);
				chunk.bytes = chunk.bytes.subarray(0, startOfs);
				return extract;
			} else {
				const rightCutInd = chunk.bytes.length - endOfs;
				const left = chunk.bytes.subarray(0, startOfs);
				const extract = chunk.bytes.subarray(startOfs, rightCutInd);
				const right = chunk.bytes.subarray(rightCutInd);
				this.chunks.splice(chunkInd+1, 0, {
					start: chunk.end - endOfs,
					end: chunk.end,
					bytes: right
				});
				chunk.bytes = left;
				chunk.end = chunk.start + startOfs;
				return extract;
			}
		}

	}

	findChunkWith(start: number, end: number): Chunk|undefined {
		if ((start < 0) || (end <= start)) { throw new Error(
			`Invalid boundaries: start = ${start}, end = ${end}`); }
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			if (chunk.end <= start) { continue; }
			if ((start < chunk.start) || (chunk.end < end)) { return; }
			return chunk;
		}
		return; // explicit undefined return
	}

	findAndExtract(start: number, end: number): Uint8Array|undefined {
		const chunk = this.findChunkWith(start, end);
		if (!chunk) { return; }
		return this.extractBytesFrom(chunk, start, end);
	}

	extractTail(): Chunk|undefined {
		if (this.chunks.length === 0) { return; }
		if (this.chunks.length > 1) { throw new Error(
			`Not all bytes were written, creating a gap`); }
		return this.chunks.pop();
	}

	extractTailIfEndsAt(end: number): Chunk|undefined {
		if (this.chunks.length === 0) { return; }
		const last = this.chunks[this.chunks.length-1];
		if (last.end < end) {
			return;
		} else if (last.end === end) {
			this.chunks.pop();
			return last;
		} else {
			throw writeExc('segsPacked',
				`Given end value cuts already written bytes`);
		}
	}

}
Object.freeze(ChunksBuffer.prototype);
Object.freeze(ChunksBuffer);

export interface HeaderEncrEvent {
	type: 'header';
	/**
	 * Packed header
	 */
	header: Uint8Array;
	/**
	 * Layout of packed bytes
	 */
	layout: Layout;
}

export interface SegEncrEvent {
	type: 'seg';
	seg: Uint8Array;
	segInfo: NewSegmentInfo;
}

export type EncrEvent = HeaderEncrEvent | SegEncrEvent;
export type Subscribe =
	(obs: Observer<EncrEvent>, backpressure?: () => Promise<void>) =>
	(() => void);

/**
 * This creates an encrypting byte writer, attached to a given observer. Writer
 * and subsribing function are returned.
 * Subscribing function takes optional backpressure function, returning an
 * unsubscribing function.
 * @param segsWriter that encrypts and packs bytes into object segments
 * @param obs is an observer of encryption events. This observer must have all
 * of its function-fields.
 */
export function makeEncryptingByteSink(
	segsWriter: SegmentsWriter
): { sink: ByteSink; sub: Subscribe; } {
	assert(segsWriter.formatVersion === 1,
		`Seg writer format is ${segsWriter.formatVersion} instead of 1`);
	return EncryptingByteSink.makeFor(segsWriter);
}

class EncryptingByteSinkWithAttrs {

	private attrSize: number|undefined = undefined;
	private attrSizeSetInThisVersion = false;
	private contentSize: number|undefined = undefined;

	private constructor(
		private readonly mainSink: ByteSink
	) {
		Object.seal(this);
	}

	private init(
		segWriter: SegmentsWriter, baseAttrSize: number|undefined
	): void {
		if (!segWriter.hasBase) { return; }
		if (baseAttrSize === undefined) { throw new Error(
			`Writer has base, but base attributes size is not given`); }
		if (!Number.isInteger(baseAttrSize)
		|| (baseAttrSize < 0)) { throw new Error (
			`Given invalid base attrs size: ${baseAttrSize}`); }
		this.attrSize = baseAttrSize;
		if (segWriter.contentLength !== undefined) {
			this.contentSize = segWriter.contentLength - (
				(this.attrSize === 0) ? 0 : 4+this.attrSize);
			if (this.contentSize < 0) { throw new Error(
				`Given base attributes' size implies negative content size`); }
		}
	}

	static makeFor(
		segWriter: SegmentsWriter, baseAttrSize: number|undefined
	): { sink: ByteSinkWithAttrs; sub: Subscribe; } {
		const { sink: mainSink, sub } = EncryptingByteSink.makeFor(segWriter);
		// Note about synchronization:
		// a) mainSink's methods are synchronized.
		// b) Methods of this class only change values of input parameters that
		//    are captured in a possible synchronization wait, but are not
		//    changed thereafter.
		// c) Only one JS thread executes at any moment.
		// Given above points, we can write all methods in this class to perform
		// all changes in a sync manner before tail-calling mainSink methods.
		// This will ensure ordered changes to state in wrap and in mainSink.
		// If few mainSink calls are done, only the first call will be
		// synchronized relative to other methods.
		const wrap = new EncryptingByteSinkWithAttrs(mainSink);
		wrap.init(segWriter, baseAttrSize);
		const sink: ByteSinkWithAttrs = {
			getSize: wrap.getSize.bind(wrap),
			setSize: wrap.setSize.bind(wrap),
			showLayout: mainSink.showLayout,
			spliceLayout: wrap.spliceLayout.bind(wrap),
			freezeLayout: wrap.freezeLayout.bind(wrap),
			write: wrap.write.bind(wrap),
			done: wrap.done.bind(wrap),
			setAttrSectionSize: wrap.setAttrSectionSize.bind(wrap),
			writeAttrs: wrap.writeAttrs.bind(wrap)
		};
		return { sink, sub };
	}

	async setAttrSectionSize(size: number): Promise<void> {
		if (!Number.isInteger(size) || (size < 0)) { throw new Error(
			`Invalid size value ${size}`); }
		if (this.attrSizeSetInThisVersion) { throw new Error(
			`Attributes' section size is already set`); }
		this.attrSizeSetInThisVersion = true;
		if (this.attrSize === undefined) {
			this.attrSize = size;
			if (this.contentSize !== undefined) {
				await this.mainSink.setSize(4 + this.attrSize + this.contentSize);
			}
		} else {
			const del = ((this.attrSize === 0) ? 0 : 4 + this.attrSize);
			this.attrSize = size;
			const ins = 4 + this.attrSize;
			await this.mainSink.spliceLayout(0, del, ins);
		}
		await this.mainSink.write(0, packUintToBytes(this.attrSize));
	}

	async writeAttrs(bytes: Uint8Array): Promise<void> {
		if (this.attrSizeSetInThisVersion) {
			if (this.attrSize !== bytes.length) { throw new Error(
				`Expected attributes' section size is ${this.attrSize}, but ${bytes.length} bytes given`); }
		} else {
			await this.setAttrSectionSize(bytes.length);
		}
		await this.mainSink.write(4, bytes);
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		const { isEndless, size } = await this.mainSink.getSize();
		const attrSize = (typeof this.attrSize === 'number') ? this.attrSize : 0;
		return { size: Math.max(0, size - 4 - attrSize), isEndless };
	}

	async setSize(size: number | undefined): Promise<void> {
		if (size === undefined) {
			this.contentSize = undefined;
			return this.mainSink.setSize(undefined);
		}
		if (!Number.isInteger(size) || (size < 0)) { throw new Error(
			`Invalid size value ${size}`); }
		this.contentSize = size;
		if (this.attrSize !== undefined) {
			return this.mainSink.setSize(4 + this.attrSize + this.contentSize);
		}
	}

	spliceLayout(pos: number, del: number, ins: number): Promise<void> {
		if (this.attrSize === undefined) { throw new Error(
			`Attributes' section size is not set, preventing layout splicing`); }
		return this.mainSink.spliceLayout(4 + this.attrSize + pos, del, ins);
	}

	freezeLayout(): Promise<void> {
		if (this.attrSize === undefined) { throw new Error(
			`Attributes' section size is not set, preventing layout freeze`); }
		return this.mainSink.freezeLayout();
	}

	write(pos: number, bytes: Uint8Array): Promise<void> {
		if (this.attrSize === undefined) { throw new Error(
			`Attributes' section size is not set, preventing write of content`); }
		return this.mainSink.write(4 + this.attrSize + pos, bytes);
	}

	done(err?: any): Promise<void> {
		if (err) {
			return this.mainSink.done(err);
		} else if (this.attrSize === undefined) {
			throw new Error(`Attributes' section size is not set, preventing write completion`);
		} else {
			return this.mainSink.done();
		}
	}

}
Object.freeze(EncryptingByteSinkWithAttrs.prototype);
Object.freeze(EncryptingByteSinkWithAttrs);

function packUintToBytes(u: number): Uint8Array {
	const b = new Uint8Array(4);
	storeUintIn4Bytes(b, 0, u);
	return b;
}

export function makeEncryptingByteSinkWithAttrs(
	segsWriter: SegmentsWriter, baseAttrSize?: number
): { sink: ByteSinkWithAttrs; sub: Subscribe; } {
	assert(segsWriter.formatVersion === 2,
		`Seg writer format is ${segsWriter.formatVersion} instead of 2`);
	return EncryptingByteSinkWithAttrs.makeFor(segsWriter, baseAttrSize);
}

Object.freeze(exports);