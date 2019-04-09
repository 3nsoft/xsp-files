/*
 Copyright (C) 2015 - 2018 3NSoft Inc.
 
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

import { ByteSource } from './common';
import { SegmentsReader } from '../segments/reader';
import { SegmentInfo } from '../segments/xsp-info';
import { assert } from '../utils/assert';


class DecryptingByteSource implements ByteSource {
	
	private segIter: IterableIterator<SegmentInfo>|undefined =
		undefined;
	private seg: SegmentInfo|undefined = undefined;
	private posInSeg = 0;
	private bufferedSeg: Uint8Array|undefined = undefined;
	private contentLen = 0;
	
	constructor(
		private segsSrc: ByteSource,
		private segReader: SegmentsReader
	) {
		Object.seal(this);
	}

	private async init(): Promise<void> {
		if (this.segReader.contentLength !== undefined) {
			this.contentLen = this.segReader.contentLength;
		}
	}

	static async makeFor(segsSrc: ByteSource, segsReader: SegmentsReader):
			Promise<ByteSource> {
		const decr = new DecryptingByteSource(segsSrc, segsReader);
		await decr.init();
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
			&& (this.segReader.isEndlessFile || (offset < this.contentLen)),
			`Given offset ${offset} is out of bounds.`);

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

	async getSize(): Promise<number|undefined> {
		if (this.segReader.isEndlessFile) {
			return;
		} else {
			return this.contentLen;
		}
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
export function makeDecryptedByteSource(segsSrc: ByteSource,
		segReader: SegmentsReader): Promise<ByteSource> {
	return DecryptingByteSource.makeFor(segsSrc, segReader);
}

Object.freeze(exports);