/*
 Copyright (C) 2018 - 2021 3NSoft Inc.
 
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

import { ByteSink, Observer, Layout, ByteSinkWithAttrs } from './common';
import { SegmentsWriter, writeExc, NewSegmentInfo, WritableSegmentInfo } from '../segments/writer';
import { LocationInSegment, storeUintIn4Bytes } from '../segments/xsp-info';
import { assert } from '../utils/assert';
import { SingleProc, makeSyncedFunc } from '../utils/process-syncing';
import { makeUint8ArrayCopy } from '../utils/buffer-utils';

class EncryptingByteSink implements ByteSink {

	private encOutput: Observer<EncrEvent>|undefined = undefined;
	private backpressure: (() => Promise<void>)|undefined = undefined;
	private isCompleted = false;
	private buffer = new ChunksBuffer();
	private biggestContentOfs: number;
	private size: number|undefined;
	private writerFlippedToEndless = false;
	private reencryptSegs: UnpackedSegsForReencryption|undefined;

	constructor(
		private segWriter: SegmentsWriter
	) {
		if (this.segWriter.hasBase) {
			this.reencryptSegs = new UnpackedSegsForReencryption(
				this.segWriter.unpackedReencryptChainSegs.bind(this.segWriter),
				this.packAndOutSeg.bind(this));
			this.size = this.segWriter.contentLength;
			this.biggestContentOfs = ((this.size === undefined) ? 0 : this.size);
		} else {
			this.reencryptSegs = undefined;
			this.size = undefined;
			this.biggestContentOfs = 0;
		}
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
		return this.stopAndSetCompleted.bind(this);
	}

	private stopAndSetCompleted(err?: any): void {
		if (this.isCompleted) { return; }
		this.isCompleted = true;
		if (this.encOutput) {
			if (err) {
				if (this.encOutput.error) { this.encOutput.error(err); }
			} else {
				if (this.encOutput.complete) { this.encOutput.complete(); }
			}
		}
		this.encOutput = undefined;
	}

	private throwUpIfCompletedOrNotSubscribed(): void {
		if (this.isCompleted) { throw new Error(`This sink has been completed`); }
		if (!this.encOutput) { throw new Error(`This sink is not subsribed to`); }
	}

	async showLayout(): Promise<Layout> {
		if (this.writerFlippedToEndless) {
			await this.segWriter.setContentLength(this.size);
			const layout = this.segWriter.showContentLayout();
			await this.segWriter.setContentLength(undefined);
			return layout;
		} else {
			return this.segWriter.showContentLayout();
		}
	}

	async spliceLayout(pos: number, del: number, ins: number): Promise<void> {
		if (this.segWriter.isHeaderPacked) { throw new Error(
			`Layout is already frozen`); }
		assert(Number.isInteger(pos) && (pos >= 0)
			&& Number.isInteger(del) && (del >= 0)
			&& Number.isInteger(ins) && (ins >= 0), `Invalid parameters given`);
		this.throwUpIfCompletedOrNotSubscribed();
		try {
			await this.segWriter.splice(pos, del, ins);
			this.buffer.splice(pos, del, ins);
			if ((pos + del) >= this.biggestContentOfs) {
				this.biggestContentOfs = Math.max(0, pos + ins);
			} else {
				this.biggestContentOfs = Math.max(0, this.biggestContentOfs - del +ins);
			}
			if (this.size !== undefined) {
				this.size = this.biggestContentOfs;
				if (!this.writerFlippedToEndless) {
					await this.segWriter.setContentLength(undefined);
					this.writerFlippedToEndless = true;
				}
			}
		} catch (err) {
			await this.done(err);
			throw err;
		}
	}

	async freezeLayout(): Promise<void> {
		this.throwUpIfCompletedOrNotSubscribed();
		if (this.segWriter.isHeaderPacked) { return; }

		try {

			if (this.writerFlippedToEndless) {
				await this.segWriter.setContentLength(this.size);
				this.writerFlippedToEndless = false;
			}

			const header = await this.segWriter.packHeader();
			if (this.backpressure) {
				await this.backpressure();
			}
			const ev: HeaderEncrEvent = {
				type: 'header',
				header,
				layout: this.segWriter.showPackedLayout()
			};
			this.encOutput!.next!(ev);

			if (this.reencryptSegs) {
				this.reencryptSegs.onLayoutFreeze();
			}

		} catch (err) {
			await this.done(err);
			throw err;
		}
	}

	async done(err?: any): Promise<void> {
		if (!this.encOutput) { throw new Error(`This sink is not subsribed to`); }
		if (this.isCompleted) { return; }
		if (err) {
			this.stopAndSetCompleted(err);
			return;
		}

		if (!this.segWriter.isHeaderPacked) {
			if (this.writerFlippedToEndless) {
				await this.segWriter.setContentLength(this.size);
				this.writerFlippedToEndless = false;
			} else if (this.size === undefined) {
				await this.segWriter.setContentLength(this.biggestContentOfs);
			}
		}

		await this.packUnpackedBytesAtSinkCompletion();

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

		await this.freezeLayout();
		this.stopAndSetCompleted();
	}

	async write(pos: number, bytes: Uint8Array): Promise<void> {
		this.throwUpIfCompletedOrNotSubscribed();
		if (this.size !== undefined) {
			if (this.size < (pos + bytes.length)) {
				throw new Error(`Writing outside of sink size. Use respective splice before write.`);
			}
		}

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

		if (this.size === undefined) {
			const endOfs = pos + bytes.length;
			if (this.biggestContentOfs < endOfs) {
				this.biggestContentOfs = endOfs;
			}
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

	private async packUnpackedBytesAtSinkCompletion(): Promise<void> {
		// try to write everything that may be stuck in a buffer
		const bufferedChunks = this.buffer.extractAllChunks();
		for (const c of bufferedChunks) {
			await this.write(c.start, c.bytes);
		}
		// case of endless file and odd length last chunk, stucking in buffer
		if (this.segWriter.isEndlessFile) {
			const tailChunk = this.buffer.extractTail();
			if (tailChunk) {
				const pos = this.segWriter.locateContentOfs(tailChunk.start);
				if (pos.posInSeg !== 0) { throw new Error(
					`There are missing bytes`); }
				const segInfo = this.segWriter.segmentInfo(pos);
				if (segInfo.type !== 'new') { throw new Error(
					`Unexpected not-new segment`); }
				await this.packAndOutSeg(segInfo, tailChunk.bytes);
			}
		}
	}

	private getWholeSegsAndBufferRest(
		pos: LocationInSegment, bytes: Uint8Array
	): [ NewSegmentInfo, Uint8Array ][] {
		const wholeSegs: [ NewSegmentInfo, Uint8Array ][] = [];
		const segs = this.segWriter.segmentInfos(pos);

		// first segment
		{
			const { value: fstSeg } = segs.next() as IteratorResult<WritableSegmentInfo, WritableSegmentInfo>;

			if (fstSeg.type === 'base') { throw writeExc('segsPacked',
				`Given bytes overlap base bytes`); }
			if (!fstSeg.needPacking) { throw writeExc('segsPacked'); }

			// fstSeg parameters, corrected for presence of head (base)
			const ofsInFstSeg = pos.posInSeg - (fstSeg.headBytes ?
				fstSeg.headBytes : 0);
			const fstSegStart = fstSeg.contentOfs +
				(fstSeg.headBytes ? fstSeg.headBytes : 0);
			const fstSegEnd = fstSeg.contentOfs +
				(fstSeg.headBytes ? fstSeg.headBytes : 0) + fstSeg.contentLen;

			if (ofsInFstSeg < 0) { throw writeExc('segsPacked',
				`Given bytes overlap base bytes`); }

			if (ofsInFstSeg === 0) {
				if (bytes.length < fstSeg.contentLen) {
					const tailStart = fstSegStart + bytes.length;
					const tailBytes = this.buffer.findAndExtract(
						tailStart, fstSegEnd);
					if (!tailBytes) {
						this.buffer.add(fstSegStart, bytes);
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
				// const headStart = fstSeg.contentOfs;
				const headEnd = fstSegStart + ofsInFstSeg;
				const headChunk = this.buffer.findChunkWith(fstSegStart, headEnd);

				if ((ofsInFstSeg + bytes.length) < fstSeg.contentLen) {
					const tailStart = headEnd + bytes.length;
					const tailChunk = this.buffer.findChunkWith(
						tailStart, fstSegEnd);
					if (!headChunk || !tailChunk) {
						this.buffer.add(headEnd, bytes);
						return wholeSegs;
					}
					const wholeSeg = new Uint8Array(fstSeg.contentLen);
					const headBytes = this.buffer.extractBytesFrom(
						headChunk, fstSegStart, headEnd);
					wholeSeg.set(headBytes);
					wholeSeg.set(bytes, headBytes.length);
					const tailBytes = this.buffer.extractBytesFrom(
						tailChunk, tailStart, fstSegEnd);
					wholeSeg.set(tailBytes, headBytes.length+bytes.length);
					wholeSegs.push([ fstSeg, wholeSeg ]);
					return wholeSegs;
				}

				const oddFstChunk = bytes.subarray(
					0, fstSeg.contentLen-ofsInFstSeg);
				bytes = bytes.subarray(oddFstChunk.length);
				if (headChunk) {
					const wholeSeg = new Uint8Array(fstSeg.contentLen);
					const headBytes = this.buffer.extractBytesFrom(
						headChunk, fstSegStart, headEnd);
					wholeSeg.set(headBytes);
					wholeSeg.set(oddFstChunk, headBytes.length);
					wholeSegs.push([ fstSeg, wholeSeg ]);
				} else {
					this.buffer.add(headEnd, oddFstChunk);
				}
			}
		}

		// other segments
		while (bytes.length > 0) {
			const { done, value: seg } = segs.next() as IteratorResult<WritableSegmentInfo, WritableSegmentInfo>;
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
		try {
			await this.segWriter.setContentLength(size);
			this.size = size;
			if (this.size === undefined) {
				this.writerFlippedToEndless = false;
			} else {
				this.buffer.cutToSize(this.size);
				this.biggestContentOfs = this.size;
				await this.segWriter.setContentLength(undefined);
				this.writerFlippedToEndless = true;
			}
		} catch (err) {
			await this.done(err);
			throw err;
		}
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		return ((this.size === undefined) ?
			{ isEndless: true, size: this.biggestContentOfs } :
			{ isEndless: false, size: this.size });
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
		for (let i=segs.length-1; i>=0; i-=1) {
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

	splice(pos: number, del: number, ins: number): void {
		const rightCutPos = pos + del;
		let i = 0;
		// we loop to find where to cut and do it
		while (i < this.chunks.length) {
			const chunk = this.chunks[i];
			if (chunk.end <= pos) {
				i += 1;
				continue;
			}
			if (rightCutPos <= chunk.start) { break; }
			if (pos <= chunk.start) {
				if (chunk.end <= rightCutPos) {
					this.chunks.splice(i, 1);
					continue;
				} else {
					const cutOfs = rightCutPos - chunk.start;
					chunk.bytes = chunk.bytes.subarray(cutOfs);
					chunk.start = rightCutPos;
					break;
				}
			} else {
				if (chunk.end <= rightCutPos) {
					const newLen = pos - chunk.start;
					chunk.bytes = chunk.bytes.subarray(0, newLen);
					chunk.end = pos;
					i += 1;
					continue;
				} else {
					const left = chunk.bytes.subarray(0, pos - chunk.start);
					const right = chunk.bytes.subarray(rightCutPos - chunk.start);
					chunk.bytes = left;
					chunk.end = pos;
					const rightChunk: Chunk = {
						bytes: right,
						start: rightCutPos,
						end: chunk.end,
					};
					i += 1;
					this.chunks.splice(i, 0, rightChunk);
					break;
				}
			}
		}
		// shift all chunks, starting with i
		const delta = ins - del;
		while (i < this.chunks.length) {
			const chunk = this.chunks[i];
			chunk.start += delta;
			chunk.end += delta;
			i += 1;
		}
	}

	add(start: number, bytes: Uint8Array): void {
		const end = start + bytes.length;
		
		for (let i=0; i<this.chunks.length; i+=1) {
			const existing = this.chunks[i];
			if (existing.end < start) { continue; }
			if (existing.end === start) {
				existing.bytes = joinBytes(existing.bytes, bytes);
				existing.end = end;
				if ((i+1) < this.chunks.length) {
					const following = this.chunks[i+1];
					if (existing.end === following.start) {
						existing.bytes = joinBytes(existing.bytes, following.bytes);
						existing.end = following.end;
						this.chunks.splice(i+1, 1);
					}
				}
			} else if (end === existing.start) {
				existing.bytes = joinBytes(bytes, existing.bytes);
				existing.start = start;
			} else {
				assert(end < existing.start,
					`Overlap of new bytes with already buffered ones`);
				// Note that below we copy bytes into new array. This is done to
				// detouch from any incoming buffers that may be shared/reused
				// elsewhere, wracking havoc here.
				this.chunks.splice(i, 0, {
					start, end, bytes: makeUint8ArrayCopy(bytes)
				});
			}
			return;
		}

		// We copy bytes here for the same reason as above.
		const newChunk: Chunk = { start, end, bytes: makeUint8ArrayCopy(bytes) };
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
				chunk.start += extract.length;
				return extract;
			}
		} else {
			if (endOfs === 0) {
				const extract = chunk.bytes.subarray(startOfs);
				chunk.bytes = chunk.bytes.subarray(0, startOfs);
				chunk.end -= extract.length;
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

	cutToSize(size: number): void {
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			if (size <= chunk.start) {
				this.chunks.splice(i, this.chunks.length);
				return;
			} else if (chunk.end <= size) {
				continue;
			} else {
				const newLen = size - chunk.start;
				chunk.bytes = chunk.bytes.subarray(0, newLen);
				chunk.end = size;
				this.chunks.splice(i+1, this.chunks.length);
				return;
			}
		}
	}

	extractAllChunks(): Chunk[] {
		if (this.chunks.length === 0) { return []; }
		return this.chunks.splice(0, this.chunks.length);
	}

}
Object.freeze(ChunksBuffer.prototype);
Object.freeze(ChunksBuffer);

function joinBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
	const joinedBytes = new Uint8Array(a.length+b.length);
	joinedBytes.set(a);
	joinedBytes.set(b, a.length);
	return joinedBytes;
}

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

	private attrSize: number|undefined;
	private attrSizeSetInThisVersion = false;
	private contentSize: number|undefined;

	private constructor(
		private readonly mainSink: ByteSink,
		private readonly baseAttrSize: number|undefined,
		segWriter: SegmentsWriter
	) {
		if (segWriter.hasBase) {
			if (this.baseAttrSize === undefined) { throw new Error(
				`Writer has base, but base attributes size is not given`); }
			if (!Number.isInteger(this.baseAttrSize)
			|| (this.baseAttrSize < 0)) { throw new Error (
				`Given invalid base attrs size: ${this.baseAttrSize}`); }
			this.attrSize = this.baseAttrSize;
			if (segWriter.contentLength !== undefined) {
				this.contentSize = segWriter.contentLength - (
					(this.attrSize === 0) ? 0 : 4+this.attrSize);
				if (this.contentSize < 0) { throw new Error(
					`Given base attributes' size implies negative content size`); }
			}
		} else {
			if (baseAttrSize !== undefined) { throw new Error(
				`Base attributes size is given, when writer has no base`); }
			this.attrSize = undefined;
			this.contentSize = undefined;
		}
		Object.seal(this);
	}

	static makeFor(
		segWriter: SegmentsWriter, baseAttrSize: number|undefined
	): { sink: ByteSinkWithAttrs; sub: Subscribe; } {
		const { sink: mainSink, sub } = EncryptingByteSink.makeFor(segWriter);
		const s = new EncryptingByteSinkWithAttrs(
			mainSink, baseAttrSize, segWriter);
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
		const sink: ByteSinkWithAttrs = {
			getSize: s.getSize.bind(s),
			setSize: s.setSize.bind(s),
			showLayout: s.showLayout.bind(s),
			spliceLayout: s.spliceLayout.bind(s),
			freezeLayout: s.freezeLayout.bind(s),
			write: s.write.bind(s),
			done: s.done.bind(s),
			setAttrSectionSize: s.setAttrSectionSize.bind(s),
			writeAttrs: s.writeAttrs.bind(s)
		};
		return { sink, sub };
	}

	async setAttrSectionSize(size: number): Promise<void> {
		if (!Number.isInteger(size) || (size < 0)) { throw new Error(
			`Invalid size value ${size}`); }
		if (this.attrSizeSetInThisVersion) { throw new Error(
			`Attributes' section size is already set`); }
		const del = (this.attrSize ? 4 + this.attrSize : 0);
		this.attrSize = size;
		const ins = 4 + this.attrSize;
		this.attrSizeSetInThisVersion = true;
		await this.mainSink.spliceLayout(0, del, ins);
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

	async showLayout(): Promise<Layout> {
		const l = await this.mainSink.showLayout();
		const attrShift = ((this.attrSize === undefined) ?
			undefined : 4 + this.attrSize);
		const baseShift = ((this.baseAttrSize === undefined) ?
			undefined : 4 + this.baseAttrSize);
		for (let i=0; i<l.sections.length; i+=1) {
			const s = l.sections[i];
			if ((s.src === 'base') && (baseShift !== undefined)) {
				if (s.baseOfs <= baseShift) {
					s.baseOfs = 0;
				} else {
					s.baseOfs -= baseShift;
				}
			}
			if (attrShift === undefined) { continue; }
			if (s.ofs <= attrShift) {
				if (s.len === undefined) {
					s.ofs = 0;
				} else if ((s.ofs + s.len) <= attrShift) {
					l.sections.splice(i, 1);
					i -= 1;
				} else {
					const delta = attrShift - s.ofs;
					s.ofs = 0;
					s.len -= delta;
				}
			} else {
				s.ofs -= attrShift;
			}
		}
		return l;
	}

	async setSize(size: number | undefined): Promise<void> {
		if (size === undefined) {
			this.contentSize = undefined;
			return this.mainSink.setSize(undefined);
		}
		if (!Number.isInteger(size) || (size < 0)) { throw new Error(
			`Invalid size value ${size}`); }
		this.contentSize = size;
		const sinkSize = this.contentSize +
			((this.attrSize === undefined) ? 0 : 4 + this.attrSize);
		await this.mainSink.setSize(sinkSize);
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