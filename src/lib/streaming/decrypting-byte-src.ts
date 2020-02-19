/*
 Copyright (C) 2015 - 2020 3NSoft Inc.
 
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

import { ByteSource, ByteSourceWithAttrs } from './common';
import { SegmentsReader } from '../segments/reader';
import { SegmentInfo, loadUintFrom4Bytes } from '../segments/xsp-info';
import { assert } from '../utils/assert';


class DecryptingByteSource implements ByteSource {
	
	private segIter: IterableIterator<SegmentInfo>|undefined =
		undefined;
	private seg: SegmentInfo|undefined = undefined;
	private posInSeg = 0;
	private bufferedSeg: Uint8Array|undefined = undefined;
	
	constructor(
		private readonly segsSrc: ByteSource,
		private readonly segReader: SegmentsReader
	) {
		Object.seal(this);
	}

	static makeFor(
		segsSrc: ByteSource, segsReader: SegmentsReader
	): ByteSource {
		const decr = new DecryptingByteSource(segsSrc, segsReader);
		const w: ByteSource = {
			read: decr.read.bind(decr),
			getSize: decr.getSize.bind(decr),
			getPosition: decr.getPosition.bind(decr),
			seek: decr.seek.bind(decr)
		};
		return w;
	}

	private get contentPosition(): number {
		if (!this.seg) { return 0; }
		return this.seg.contentOfs + this.posInSeg;
	}

	async getPosition(): Promise<number> {
		return this.contentPosition;
	}

	async seek(offset: number): Promise<void> {
		if (offset === this.contentPosition) { return; }

		assert(Number.isInteger(offset) && (offset >= 0)
			&& (this.segReader.isEndlessFile || (offset <= this.segReader.contentLength!)),
			`Given offset ${offset} is out of bounds.`);

		// special case of seeking to the very end
		if (!this.segReader.isEndlessFile
		&& (offset === this.segReader.contentLength)) {
			assert(this.segReader.contentLength > 0);
			await this.seek(this.segReader.contentLength-1);
			this.posInSeg += 1;
			return;
		}

		const l = this.segReader.locateContentOfs(offset);

		if (this.seg && (this.seg.chain === l.chain)
		&& (this.seg.seg === l.seg)) {
			this.posInSeg = l.posInSeg;
			return;
		}

		const iter = this.segReader.segmentInfos(l);
		const { done, value } = iter.next();
		assert(!done, `Unexpected end of iteration`);

		this.segIter = iter;
		this.seg = value;
		this.bufferedSeg = undefined;
		this.posInSeg = l.posInSeg;
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		return {
			isEndless: this.segReader.isEndlessFile,
			size: this.segReader.contentFiniteLength
		};
	}

	read(len: number|undefined): Promise<Uint8Array|undefined> {
		if (!this.segIter) {
			this.segIter = this.segReader.segmentInfos();
		}
		if (len === undefined) {
			return this.readToTheEnd();
		} else {
			assert(Number.isInteger(len) && (len > 0), `Invalid length given`);
			return this.readLimitedLen(len);
		}
	}

	private async readToTheEnd(): Promise<Uint8Array|undefined> {
		const chunks: Uint8Array[] = [];

		// read from current seg, if position allows
		if (this.seg && (this.posInSeg < this.seg.contentLen)) {
			if (!this.bufferedSeg) {
				this.bufferedSeg = await this.readAndDecryptSeg();
			}
			const extract = ((this.posInSeg === 0) ?
				this.bufferedSeg : this.bufferedSeg.subarray(this.posInSeg));
			chunks.push(extract);
			this.posInSeg = this.bufferedSeg.length;
		}

		// move to next segments
		let { done, value: nextSeg } = this.segIter!.next();
		while (!done) {
			this.seg = nextSeg;
			this.posInSeg = 0;
			this.bufferedSeg = await this.readAndDecryptSeg();
			chunks.push(this.bufferedSeg);
			this.posInSeg = this.bufferedSeg.length;
			({ done, value: nextSeg } = this.segIter!.next());
		}

		return joinByteArrays(chunks);
	}

	private async readLimitedLen(len: number): Promise<Uint8Array|undefined> {
		const chunks: Uint8Array[] = [];

		// read from current seg, if position allows
		if (this.seg && (this.posInSeg < this.seg.contentLen)) {
			if (!this.bufferedSeg) {
				this.bufferedSeg = await this.readAndDecryptSeg();
			}
	
			const available = this.bufferedSeg.length - this.posInSeg;
			if (available >= len) {
				const extract = this.bufferedSeg.subarray(
					this.posInSeg, this.posInSeg + len);
				this.posInSeg += len;
				return extract;
			} else {
				const extract = ((this.posInSeg === 0) ?
					this.bufferedSeg : this.bufferedSeg.subarray(this.posInSeg));
				chunks.push(extract);
				this.posInSeg = this.bufferedSeg.length;
				len -= extract.length;
			}
		}

		// move to next segments
		let { done, value: nextSeg } = this.segIter!.next();
		while (!done) {
			this.seg = nextSeg;
			this.posInSeg = 0;
			this.bufferedSeg = await this.readAndDecryptSeg();

			if (this.bufferedSeg.length > len) {
				const extract = this.bufferedSeg.subarray(0, len);
				this.posInSeg += len;
				chunks.push(extract);
				return joinByteArrays(chunks);
			} else {
				chunks.push(this.bufferedSeg);
				this.posInSeg = this.bufferedSeg.length;
				len -= this.bufferedSeg.length;
			}

			if (len > 0) {
				({ done, value: nextSeg } = this.segIter!.next());
			} else {
				break;
			}
		}

		return joinByteArrays(chunks);
	}

	private async readAndDecryptSeg(): Promise<Uint8Array> {
		await this.segsSrc.seek(this.seg!.packedOfs);
		const segBytes = await this.segsSrc.read(this.seg!.packedLen);
		if (!segBytes) { throw new Error(
			`EOF: source of packed segments unexpectidly ended`); }
		return await this.segReader.openSeg(this.seg!, segBytes);
	}

}

function joinByteArrays(arrs: Uint8Array[]): Uint8Array|undefined {
	const totalLen = totalLengthOf(arrs);
	if (totalLen === 0) { return; }
	const join = new Uint8Array(totalLen);
	let ofs = 0;
	for (const arr of arrs) {
		join.set(arr, ofs);
		ofs += arr.length;
	}
	return join;
}

function totalLengthOf(arrs: Uint8Array[]): number {
	let len = 0;
	for (let i=0; i<arrs.length; i+=1) {
		len += arrs[i].length;
	}
	return len;
}

/**
 */
export function makeDecryptedByteSource(
	segsSrc: ByteSource, segReader: SegmentsReader
): ByteSource {
	assert(segReader.formatVersion === 1,
		`Seg reader format is ${segReader.formatVersion} instead of 1`);
	return DecryptingByteSource.makeFor(segsSrc, segReader);
}

class DecryptingByteSourceWithAttrs {

	private constructor(
		private readonly mainSrc: ByteSource,
		private readonly attrSize: number
		) {
		Object.freeze(this);
	}

	static async makeFor(
		segsSrc: ByteSource, segsReader: SegmentsReader
	): Promise<ByteSourceWithAttrs> {
		const mainSrc = DecryptingByteSource.makeFor(segsSrc, segsReader);
		const attrSizeBytes = await mainSrc.read(4);
		if (!attrSizeBytes || (attrSizeBytes.length < 4)) { throw new Error(
			`Too few bytes in a source`); }
		const attrSize = loadUintFrom4Bytes(attrSizeBytes, 0);
		await mainSrc.seek(4 + attrSize);
		if ((await mainSrc.getPosition()) < (4 + attrSize)) { throw new Error(
			`Byte source is shorter than attributes length`); }
		const wrap = new DecryptingByteSourceWithAttrs(mainSrc, attrSize);
		const src: ByteSourceWithAttrs = {
			getPosition: wrap.getPosition.bind(wrap),
			getSize: wrap.getSize.bind(wrap),
			read: mainSrc.read,
			readAttrs: wrap.readAttrs.bind(wrap),
			seek: wrap.seek.bind(wrap),
			getAttrsSize: async () => { return wrap.attrSize; }
		};
		return src;
	}

	async readAttrs(): Promise<Uint8Array> {
		const initPos = await this.getPosition();
		await this.mainSrc.seek(4);
		const attrs = await this.mainSrc.read(this.attrSize);
		await this.seek(initPos);
		if (!attrs || (attrs.length !== this.attrSize)) { throw new Error(
			`Can't read expected attributes' bytes`); }
		return attrs;
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		const { isEndless, size } = await this.mainSrc.getSize();
		return { size: Math.max(0, size - 4 - this.attrSize), isEndless };
	}

	async seek(offset: number): Promise<void> {
		if (!Number.isInteger(offset) || (offset < 0)) { throw new Error(
			`Given invalid offset: ${offset}`); }
		await this.mainSrc.seek(4 + this.attrSize + offset);
	}

	async getPosition(): Promise<number> {
		const p = (await this.mainSrc.getPosition()) - this.attrSize - 4;
		if (p < 0) { throw new Error(
			`Await reading of attributes before calling this function`); }
		return p;
	}

}
Object.freeze(DecryptingByteSourceWithAttrs.prototype);
Object.freeze(DecryptingByteSourceWithAttrs);

export function makeDecryptedByteSourceWithAttrs(
	segsSrc: ByteSource, segReader: SegmentsReader
): Promise<ByteSourceWithAttrs> {
	assert(segReader.formatVersion === 2,
		`Seg reader format is ${segReader.formatVersion} instead of 2`);
	return DecryptingByteSourceWithAttrs.makeFor(segsSrc, segReader);
}

Object.freeze(exports);