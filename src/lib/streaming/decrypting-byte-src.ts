/*
 Copyright (C) 2015 - 2020, 2022 3NSoft Inc.
 
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

import { ByteSource } from './common';
import { SegmentsReader } from '../segments/reader';
import { SegmentInfo } from '../segments/xsp-info';
import { assert } from '../utils/assert';


class DecryptingByteSource implements ByteSource {

	private contentPosition = 0;
	private currentRead: Promise<ReadProcResult>|undefined = undefined;
	private buffered: BufferedOpenedSeg|undefined = undefined;

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
			readAt: decr.readAt.bind(decr),
			readNext: decr.readNext.bind(decr),
			getSize: decr.getSize.bind(decr),
			getPosition: decr.getPosition.bind(decr),
			seek: decr.seek.bind(decr)
		};
		return w;
	}

	async getPosition(): Promise<number> {
		return this.contentPosition;
	}

	async seek(offset: number): Promise<void> {
		assert(Number.isInteger(offset) && (offset >= 0)
			&& (this.segReader.isEndlessFile || (offset <= this.segReader.contentLength!)),
			`Given offset ${offset} is out of bounds.`
		);
		this.ensureNotReadingNow();
		this.contentPosition = offset;
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		return {
			isEndless: this.segReader.isEndlessFile,
			size: this.segReader.contentFiniteLength
		};
	}

	async readNext(len: number|undefined): Promise<Uint8Array|undefined> {
		if (len !== undefined) {
			assert(Number.isInteger(len) && (len > 0), `Invalid length given`);
		}
		this.ensureNotReadingNow();
		this.currentRead = this.startReadProcAt(this.contentPosition, len);
		try {
			const { opened, tail } = await this.currentRead;
			if (opened) {
				this.contentPosition += opened.length;
			}
			this.buffered = tail;
			return opened;
		} finally {
			this.currentRead = undefined;
		}
	}

	async readAt(
		pos: number, len: number|undefined
	): Promise<Uint8Array|undefined> {
		await this.seek(pos);
		return await this.readNext(len);
	}

	private ensureNotReadingNow(): void {
		if (this.currentRead) {
			throw Error(`Decrypting byte source is currently performing read operation, wait till its completion`);
		}
	}

	private startReadProcAt(
		contentOfs: number, len: number|undefined
	): Promise<ReadProcResult> {
		if (contentOfs === 0) {
			const iter = this.segReader.segmentInfos();
			this.buffered = undefined;
			return this.readSegsAndDecrypt(iter, len, undefined, 0);
		}
		if (this.segReader.contentFiniteLength <= contentOfs) {
			return Promise.resolve({});
		}

		const l = this.segReader.locateContentOfs(contentOfs);
		const iter = this.segReader.segmentInfos(l);
		let fstOpenedSeg: Uint8Array|undefined = undefined;
		if (this.buffered) {
			const { chain, seg } = this.buffered.seg;
			if ((l.chain === chain) && (l.seg === seg)) {
				iter.next();	// skip first, as it is already buffered
				fstOpenedSeg = this.buffered.bytes.subarray(l.posInSeg);
				if (len && (len <= fstOpenedSeg.length)) {
					const opened = fstOpenedSeg.subarray(0, len);
					const tail = this.buffered;
					this.buffered = undefined;
					return Promise.resolve({ opened, tail });
				} else {
					return this.readSegsAndDecrypt(iter, len, fstOpenedSeg, 0);
				}
			}
			this.buffered = undefined;
		}

		return this.readSegsAndDecrypt(iter, len, fstOpenedSeg, l.posInSeg);
	}

	private async readSegsAndDecrypt(
		segIter: IterableIterator<SegmentInfo>, len: number|undefined,
		fstOpenedSeg: Uint8Array|undefined, posInFstSeg: number
	): Promise<ReadProcResult> {
		const openedSegs: Uint8Array[] = [];
		let adjustFstSeg: boolean;
		if (fstOpenedSeg) {
			openedSegs.push(fstOpenedSeg);
			if (len !== undefined) {
				len -= fstOpenedSeg.length;
				assert(len > 0);
			}
			adjustFstSeg = false;
		} else {
			adjustFstSeg = (posInFstSeg !== 0);
		}

		let lastSeg: SegmentInfo|undefined = undefined;
		for (const {
			packedSegs: { ofs: chunkOfs, len: lenToRead }, segInfos
		} of byContinuouslyPackedSections(segIter, len, PACKED_READ_CHUNK_LEN)) {
			const chunkWithPacked = (await this.segsSrc.readAt(
				chunkOfs, lenToRead
			))!;
			assert(!!chunkWithPacked);
			while (segInfos.length > 0) {
				const batchSize = this.segReader.canStartNumOfOpeningOps();
				if ((batchSize <= 1) || (segInfos.length < 2)) {
					const segInfo = segInfos.shift()!;
					let openedSeg = await this.openSeg(
						segInfo, chunkWithPacked, chunkOfs
					);
					openedSegs.push(openedSeg);
					if (len !== undefined) {
						len -= openedSeg.length;
					}
					lastSeg = segInfo;
				} else {
					const segsToOpen = segInfos.splice(
						0, Math.min(segInfos.length, batchSize)
					);
					const openedBatch = await Promise.all(segsToOpen.map(
						segInfo => this.openSeg(segInfo, chunkWithPacked, chunkOfs)
					));
					openedSegs.push(...openedBatch);
					if (len !== undefined) {
						len -= totalLengthOf(openedBatch);
					}
					lastSeg = segsToOpen[segsToOpen.length-1];
				}
			}
		}

		let tail: ReadProcResult['tail'] = undefined;
		if (openedSegs.length === 1) {
			const openedSeg = openedSegs[0];
			if (adjustFstSeg) {
				openedSegs[0] = openedSeg.subarray(posInFstSeg);
				if (len !== undefined) {
					len += posInFstSeg;
				}
			}
			if ((len !== undefined) && (len < 0)) {
				const lastOpened = openedSegs[0];
				tail = { seg: lastSeg!, bytes: openedSeg };
				const lenForRead = lastOpened.length + len;
				assert(lenForRead > 0);
				openedSegs[0] = lastOpened.subarray(0, lenForRead);	
			}
		} else if (openedSegs.length > 1) {
			if (adjustFstSeg) {
				openedSegs[0] = openedSegs[0].subarray(posInFstSeg);
				if (len !== undefined) {
					len += posInFstSeg;
				}
			}
			if ((len !== undefined) && (len < 0)) {
				const lastOpened = openedSegs[openedSegs.length-1];
				tail = { seg: lastSeg!, bytes: lastOpened };
				const lenForRead = lastOpened.length + len;
				assert(lenForRead > 0);
				openedSegs[openedSegs.length-1] = lastOpened.subarray(
					0, lenForRead
				);	
			}
		}
		return {
			opened: joinByteArrays(openedSegs),
			tail
		};
	}

	private openSeg(
		segInfo: SegmentInfo, chunkWithPacked: Uint8Array, chunkOfs: number
	): Promise<Uint8Array> {
		const ofsInEncrSegs = segInfo.packedOfs - chunkOfs;
		const packedSeg = chunkWithPacked.subarray(
			ofsInEncrSegs, ofsInEncrSegs + segInfo.packedLen
		);
		return this.segReader.openSeg(segInfo, packedSeg);
	}

}
Object.freeze(DecryptingByteSource.prototype);
Object.freeze(DecryptingByteSource);


interface BufferedOpenedSeg {
	seg: SegmentInfo;
	bytes: Uint8Array;
}

interface ReadProcResult {
	opened?: Uint8Array;
	tail?: BufferedOpenedSeg;
}

const PACKED_READ_CHUNK_LEN = 256 * 1024;

function* byContinuouslyPackedSections(
	segIter: IterableIterator<SegmentInfo>, contentLen: number|undefined,
	packedChunkLen: number
): Generator<{
	packedSegs: { ofs: number; len: number; },
	segInfos: SegmentInfo[];
}> {
	let segInfos: SegmentInfo[] = [];
	let ofs = -1;
	let len = -1;
	for (const s of segIter) {
		if ((ofs + len) === s.packedOfs) {
			if ((len + s.packedLen) > packedChunkLen) {
				yield { packedSegs: { ofs, len }, segInfos };
				ofs = s.packedOfs;
				len = s.packedLen;
				segInfos = [ s ];
			} else {
				len += s.packedLen;
				segInfos.push(s);	
			}
		} else if (segInfos.length === 0) {
			ofs = s.packedOfs;
			len = s.packedLen;
			segInfos.push(s);
		} else {
			yield { packedSegs: { ofs, len }, segInfos };
			ofs = s.packedOfs;
			len = s.packedLen;
			segInfos = [ s ];
		}
		if (contentLen !== undefined) {
			contentLen -= s.contentLen;
			if (contentLen <= 0) {
				break;
			}
		}
	}
	if (segInfos.length > 0) {
		yield { packedSegs: { ofs, len }, segInfos };
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

export function makeDecryptedByteSource(
	segsSrc: ByteSource, segReader: SegmentsReader
): ByteSource {
	assert(segReader.formatVersion === 1,
		`Seg reader format is ${segReader.formatVersion} instead of 1`);
	return DecryptingByteSource.makeFor(segsSrc, segReader);
}


Object.freeze(exports);