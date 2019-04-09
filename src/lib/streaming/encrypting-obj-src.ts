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

import { ObjSource, ByteSource } from './common';
import { SegmentsWriter, WritableSegmentInfo } from '../segments/writer';
import { assert } from '../utils/assert';

/**
 * Use this function when byte array(s) should be encrypted.
 * Function returns an object source that does actual computations.
 * @param bytes is an array of byte arrays with content, and it can be
 * modified after this call, as all encryption is done within this call,
 * and given content array is not used by resultant source over its lifetime.
 * @param segWriter is a new/fresh/without-base writer that encrypts bytes into
 * segments. Segments writer can be destroyed after this call, as it is not
 * used by resultant source over its lifetime.
 * @param objVersion
 */
export async function makeObjSourceFromArrays(arrs: Uint8Array|Uint8Array[],
		segWriter: SegmentsWriter): Promise<ObjSource> {
	if (!Array.isArray(arrs)) {
		arrs = [ arrs ];
	}
	await segWriter.setContentLength(totalLengthOf(arrs));
	const arrsReader = new ReaderFromArrayOfBytes(arrs);
	const packedSegs: Uint8Array[] = [];
	for (const s of segWriter.segmentInfos()) {
		const content = arrsReader.getNext(s.contentLen);
		packedSegs.push(await segWriter.packSeg(content, s));
	}
	const header = await segWriter.packHeader();
	const version = segWriter.version;
	return makeNonSeekableObjSrcFromSegs(version, header, packedSegs);
}

function totalLengthOf(arrs: Uint8Array[]): number {
	let len = 0;
	for (let i=0; i<arrs.length; i+=1) {
		len += arrs[i].length;
	}
	return len;
}

class ReaderFromArrayOfBytes {

	private arrOfs = 0;
	private byteOfs = 0;

	constructor(
		private arrs: Uint8Array[]
	) {
		Object.seal(this);
	}

	getNext(len: number): Uint8Array {
		if (len < 1) { throw new Error(`Illegal length given: ${len}`); }
		const buf = new Uint8Array(len);
		let bufOfs = 0;
		for (; this.arrOfs<this.arrs.length; this.arrOfs+=1) {
			const needBytes = len - bufOfs;
			const arr = this.arrs[this.arrOfs];
			const ableToRead = arr.length - this.byteOfs;
			if (needBytes <= ableToRead) {
				// fill buffer completely and return here
				buf.set(arr.subarray(this.byteOfs, this.byteOfs+needBytes), bufOfs);
				this.byteOfs += needBytes;
				return buf;
			}
			// read partial thing and continue by default
			buf.set(arr.subarray(this.byteOfs), bufOfs);
			bufOfs += ableToRead;
			this.byteOfs = 0;
		}
		return buf.subarray(0, bufOfs);
	}

}
Object.freeze(ReaderFromArrayOfBytes.prototype);
Object.freeze(ReaderFromArrayOfBytes);

function makeNonSeekableSrcFromArrays(arrs: Uint8Array[]): ByteSource {
	const reader = new ReaderFromArrayOfBytes(arrs);
	const totalLen = totalLengthOf(arrs);
	let position = 0;
	const src: ByteSource = {
		getSize: async () => totalLen,
		read: async (len) => {
			if (len === undefined) {
				len = totalLen - position;
				if (len < 1) { return; }
			}
			const chunk = reader.getNext(len);
			return ((chunk.length === 0) ? undefined : chunk);
		},
		seek: async () => { throw new Error(`This byte source can't seek`); },
		getPosition: async () => position
	};
	return src;
}

function makeNonSeekableObjSrcFromSegs(version: number,
		header: Uint8Array, segs: Uint8Array[]): ObjSource {
	const src: ObjSource = {
		version,
		readHeader: async () => header,
		segSrc: makeNonSeekableSrcFromArrays(segs)
	};
	return src;
}

class EncryptingObjSource implements ObjSource, ByteSource {

	private segIter: IterableIterator<WritableSegmentInfo> = undefined as any;
	private seg: WritableSegmentInfo|undefined = undefined;
	private posInSeg = 0;
	private bufferedSeg: Uint8Array|undefined = undefined;
	private segIsRead = false;

	segSrc: ByteSource = {
		read: this.read.bind(this),
		getSize: this.getSize.bind(this),
		getPosition: this.getPosition.bind(this),
		seek: this.seek.bind(this)
	};

	private constructor(
		private byteSrc: ByteSource,
		private segWriter: SegmentsWriter
	) {
		Object.seal(this);
	}

	private async init(): Promise<void> {
		const srcContentLen = await this.byteSrc.getSize();
		if (this.segWriter.isHeaderPacked) {
			const writerContentLen = this.segWriter.contentLength;
			if ((writerContentLen !== undefined)
			&& (srcContentLen !== writerContentLen)) { throw new Error(
				`Given restarted writer expects content length to be "${this.segWriter.contentLength}", while given content source has length ${srcContentLen}`); }
		} else {
			if (srcContentLen !== undefined) {
				await this.segWriter.setContentLength(srcContentLen);
			}
		}
		this.segIter = this.segWriter.segmentInfos();
	}

	static async makeFor(byteSrc: ByteSource, segWriter: SegmentsWriter):
			Promise<ObjSource> {
		if (segWriter.hasBase) { throw new Error(
			`This implementation uses new writers, or restarted writers`); }
		const src = new EncryptingObjSource(byteSrc, segWriter);
		await src.init();
		const w: ObjSource = {
			version: src.version,
			readHeader: src.readHeader.bind(src),
			segSrc: src.segSrc
		};
		return w;
	}

	get version(): number {
		return this.segWriter.version;
	}

	async readHeader(): Promise<Uint8Array> {
		if (this.segWriter.isEndlessFile) {
			// set sizes, as a side effect of calling getSize()
			await this.getSize();
		}
		// get header for a known size, or for an undefined length
		const h = await this.segWriter.packHeader();
		return h;
	}

	async getSize(): Promise<number|undefined> {
		if (this.segWriter.isEndlessFile) {
			const contentLen = await this.byteSrc.getSize();
			if (contentLen !== undefined) {
				await this.segWriter.setContentLength(contentLen);
			}
		}
		return this.segWriter.segmentsLength;
	}

	async read(len: number|undefined): Promise<Uint8Array|undefined> {
		let bytes: Uint8Array;
		if (len === undefined) {
			bytes = await this.readToTheEnd();
		} else {
			assert(Number.isInteger(len) && (len > 0), `Invalid length given`);
			bytes = await this.readLimitedLen(len);
		}
		return ((bytes.length > 0) ? bytes : undefined);
	}

	private async readLimitedLen(len: number): Promise<Uint8Array> {
		const res = new Uint8Array(len);
		let ofs = 0;

		while (ofs < len) {

			if (!this.seg || this.segIsRead) {
				const haveNextSeg = this.advanceSeg();
				if (!haveNextSeg) { return res.subarray(0, ofs); }
			}

			if (!this.bufferedSeg) {
				await this.prepBufferedSeg();
				if (!this.bufferedSeg) { return res.subarray(0, ofs); }
			}

			ofs += this.copyBufferedSegInto(res, ofs);
		}

		return res.subarray(0, ofs);
	}

	private advanceSeg(): boolean {
		const { done, value } = this.segIter.next();
		if (done) {
			return false; }
		this.seg = value;
		this.posInSeg = 0;
		this.segIsRead = false;
		return true;
	}

	private async prepBufferedSeg(): Promise<void> {
		const content = await this.byteSrc.read(this.seg!.contentLen);

		if (!content) {
			if (!this.segWriter.isEndlessFile) { throw new Error(
				`Unexpected end of content bytes for encryption.`); }
			this.segIsRead = true;
			return;
		}

		if (!this.segWriter.isEndlessFile
		&& (content.length < this.seg!.contentLen)) {
			throw new Error(
			`Unexpected end of content bytes for encryption.`); }

		this.bufferedSeg = await this.segWriter.packSeg(content, this.seg!);
	}

	private copyBufferedSegInto(out: Uint8Array, ofs: number): number {
		if (!this.bufferedSeg) { throw new Error(`Buffered bytes missing`); }
		const buf = ((this.posInSeg > 0) ?
			this.bufferedSeg.subarray(this.posInSeg) : this.bufferedSeg);
		const bufLen = buf.length;
		const bucketLen = out.length - ofs;

		if (bufLen > bucketLen) {
			out.set(buf.subarray(0, bucketLen), ofs);
			this.posInSeg += bucketLen;
			return bucketLen;
		} else {
			out.set(buf, ofs);
			this.bufferedSeg = undefined;
			this.posInSeg += bufLen;
			this.segIsRead = true;
			return bufLen;
		}
	}

	private async readToTheEnd(): Promise<Uint8Array> {
		const readyBytes: Uint8Array[] = [];
		while (true) {

			if (!this.seg || this.segIsRead) {
				const haveNextSeg = this.advanceSeg();
				if (!haveNextSeg) { return toOneArray(readyBytes); }
			}

			if (!this.bufferedSeg) {
				await this.prepBufferedSeg();
				if (!this.bufferedSeg) { return toOneArray(readyBytes); }
			}

			readyBytes.push(this.extractBufferedSeg());
		}
	}

	private extractBufferedSeg(): Uint8Array {
		if (!this.bufferedSeg) { throw new Error(`Buffered bytes missing`); }
		const extract = ((this.posInSeg === 0) ?
			this.bufferedSeg : this.bufferedSeg.subarray(this.posInSeg));
		this.posInSeg += extract.length;
		this.bufferedSeg = undefined;
		this.segIsRead = true;
		return extract;
	}

	async seek(offset: number): Promise<void> {
		assert(Number.isInteger(offset) && (offset >= 0)
			&& (this.segWriter.isEndlessFile || (offset <= this.segWriter.segmentsLength!)),
			`Given offset ${offset} is out of bounds.`);

		// case of seeking to the end
		if (this.segWriter.isEndlessFile!
		&& (offset === this.segWriter.segmentsLength!)) {
			if (offset === 0) { return; }
			const lastSeg = this.segWriter.locateContentOfs(offset-1);
			this.segIter = this.segWriter.segmentInfos(lastSeg);
			({ value: this.seg } = this.segIter.next());
			this.posInSeg = this.seg.packedLen;
			this.bufferedSeg = undefined;
			return;
		}

		if (this.seg) {
			const delta = offset - (this.seg.packedOfs + this.posInSeg);

			// do nothing case
			if (delta === 0) { return; }

			if (delta < 0) { throw new Error(
				`This implementation is not allowing seeking backwards`); }

			if ((this.posInSeg + delta) < this.seg.packedLen) {
				this.posInSeg += delta;
				return;
			}
		} else if (offset === 0) {
			return;
		}

		const segLoc = this.segWriter.locateSegsOfs(offset);
		this.segIter = this.segWriter.segmentInfos(segLoc);
		({ value: this.seg } = this.segIter.next());
		this.posInSeg = segLoc.posInSeg;
		this.bufferedSeg = undefined;
		await this.byteSrc.seek(this.seg.packedOfs);
	}

	private get position(): number {
		if (!this.seg) { return 0; }
		return (this.seg.packedOfs + this.posInSeg);
	}

	async getPosition(): Promise<number> {
		return this.position;
	}

}
Object.freeze(EncryptingObjSource.prototype);
Object.freeze(EncryptingObjSource);

function toOneArray(arrs: Uint8Array[]): Uint8Array {
	const len = totalLengthOf(arrs);
	const all = new Uint8Array(len);
	let ofs = 0;
	for (let i=0; i<arrs.length; i+=1) {
		const arr = arrs[i];
		all.set(arr, ofs);
		ofs += arr.length;
	}
	return all;
}

/**
 * This wraps a given content byte source into encrypting obj source.
 * Sources are processes that are driven by reads, and encryption happens
 * when a read is called.
 * Returned source is seekable. Yet, reading of the same section twice produces
 * errors, cause underlying segment writer is not allowed to encrypt same
 * segment twice. For the same reason and for the sake of implementation
 * simplicity, seeking is only allowed forward, deviating from a full contract
 * of source with seek functionality.
 * @param bytes is a source of content bytes, which we want to encrypt.
 * @param segWriter is writer to be used for encryption.
 * If writer has base, new source starts where base bytes end, appending
 * new bytes. In other words, source gives only segments with new bytes.
 * Note 1: any splicing with writer will render in-operable a returned obj
 * source.
 * Note 2: segment writer doesn't allow encryption second time. This will
 * translate into inability for a returned source to read twice at the same
 * offset.
 */
export function makeEncryptingObjSource(bytes: ByteSource,
		segWriter: SegmentsWriter): Promise<ObjSource> {
	return EncryptingObjSource.makeFor(bytes, segWriter);
}

Object.freeze(exports);