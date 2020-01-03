/*
 Copyright(c) 2015 - 2019 3NSoft Inc.
 
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

import { LocationInSegment, SegId, SegmentInfo, SegsInfo,
	readSegsInfoFromHeader, Exception, makeBaseException }
	from './xsp-info';
import { AsyncSBoxCryptor, calculateNonce, KEY_LENGTH, NONCE_LENGTH }
	from '../utils/crypt-utils';
import { ObjSource, Layout } from '../streaming/common';
import { assert } from '../utils/assert';
import { PackingInfo, NewPackInfo } from './packing-info';

export interface SegmentsWriter {

	/**
	 * Is true, if this file is endless, and false, otherwise.
	 */
	readonly isEndlessFile: boolean;

	/**
	 * Number of content bytes, encrypted in this file. If file is endless,
	 * undefined is returned.
	 */
	readonly contentLength: number|undefined;

	readonly segmentsLength: number|undefined;

	segmentInfo(segId: SegId): WritableSegmentInfo;

	segmentInfos(fstSeg?: SegId): IterableIterator<WritableSegmentInfo>;

	readonly version: number;

	readonly defaultSegSize: number;

	/**
	 * This returns location in segment, corresponding to a given position in
	 * content.
	 * @param pos is byte's position index in file content.
	 */
	locateContentOfs(pos: number): LocationInSegment;

	locateSegsOfs(segsOfs: number): LocationInSegment;
	
	packSeg(content: Uint8Array, segId: SegId): Promise<Uint8Array>;

	showContentLayout(): Layout;

	showPackedLayout(): Layout;

	/**
	 * This wipes file key.
	 */
	destroy(): void;

	packHeader(): Promise<Uint8Array>;
	
	setContentLength(totalContentLen: number|undefined): Promise<void>;
	
	readonly isHeaderPacked: boolean;

	readonly areSegmentsPacked: boolean;
	
	splice(pos: number, rem: number, ins: number): Promise<void>;

	readonly hasBase: boolean;

	unpackedReencryptChainSegs(): NewSegmentInfo[];

	formatVersion: number;

}

export interface BaseSegmentInfo extends SegmentInfo {
	type: 'base';
	baseOfs: number;
	baseContentOfs: number;
}

export interface NewSegmentInfo extends SegmentInfo {
	type: 'new';
	headBytes?: number;
	needPacking?: boolean;
}

export type WritableSegmentInfo = NewSegmentInfo | BaseSegmentInfo;

export type RNG = (n: number) => Promise<Uint8Array>;

/**
 * This returns a promise, resolvable to segments writer.
 * @param key
 * @param zerothHeaderNonce this nonce array, advanced according to given
 * version, is used as header's nonce for this version
 * @param version
 * @param opt is a setting options objects allowing to create new writer,
 * writer on top of some base, or a restarted new writer.
 * @param rng
 * @param cryptor
 */
export async function makeSegmentsWriter(
	key: Uint8Array, zerothHeaderNonce: Uint8Array, version: number,
	opt: SegmentWriterMakeOpt, rng: RNG, cryptor: AsyncSBoxCryptor
): Promise<SegmentsWriter> {
	if (opt.type === 'new') {
		const format = (opt.formatWithSections ? 2 : 1);
		return await SegWriter.makeFresh(
			key, zerothHeaderNonce, opt.segSize, format, version, rng, cryptor);
	} else if (opt.type === 'restart') {
		return await SegWriter.makeRestarted(
			key, zerothHeaderNonce, opt.header, version, rng, cryptor);
	} else if (opt.type === 'update') {
		return await SegWriter.makeUpdated(
			key, zerothHeaderNonce, opt.base, version, rng, cryptor);
	} else {
		throw new Error(`Given unknown option type`);
	}
}

export type SegmentWriterMakeOpt =
	{ type: 'new'; segSize: number; formatWithSections?: boolean; } |
	{ type: 'update'; base: ObjSource; formatWithSections?: boolean; } |
	{ type: 'restart'; header: Uint8Array; };

class SegWriter {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;

	private packing: PackingInfo;

	private headerNonce: Uint8Array;
	
	/**
	 * @param key
	 * @param zerothNonce this nonce array, advanced according to given
	 * version, is used as header's nonce for this new version
	 * @param segsOrSegSize
	 * @param version
	 * @param randomBytes
	 * @param cryptor
	 * @param base
	 */
	private constructor(
		key: Uint8Array, zerothNonce: Uint8Array,
		baseSegs: SegsInfo|undefined, newPackInfo: NewPackInfo|undefined,
		public version: number,
		private randomBytes: RNG,
		private cryptor: AsyncSBoxCryptor,
		private base?: ObjSource
	) {
		if (key.length !== KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
		if (this.base) {
			if (!baseSegs) { throw new Error(`Base segments should be given`); }
			this.packing = PackingInfo.make(
				baseSegs, undefined, this.randomBytes, this.base.version);
		} else if (newPackInfo) {
			this.packing = PackingInfo.make(
				undefined, newPackInfo, this.randomBytes);
		} else if (baseSegs) {
			this.packing = PackingInfo.restartWithAllNewFrozenLayout(baseSegs);
		} else {
			throw new Error(``);
		}
		if (!Number.isInteger(this.version) || (this.version < 0)) {
			throw new Error(`Given version is not a non-negative integer`); }
		if (zerothNonce.length !== NONCE_LENGTH) { throw new Error(
			"Given zeroth header nonce has wrong size."); }
		this.headerNonce = ((this.version > 0) ?
			calculateNonce(zerothNonce, this.version) :
			new Uint8Array(zerothNonce));
		Object.seal(this);
	}

	static async makeFresh(
		key: Uint8Array, zerothNonce: Uint8Array,
		segSizein256bs: number, formatVersion: number,
		version: number, randomBytes: RNG, cryptor: AsyncSBoxCryptor
	): Promise<SegmentsWriter> {
		if ((segSizein256bs < 1) || (segSizein256bs > 0xffff)) {
			throw new Error("Given segment size is illegal.");
		}
		const newPackInfo: NewPackInfo = {
			formatVersion,
			segSize: segSizein256bs << 8
		};
		const segWriter = new SegWriter(
			key, zerothNonce, undefined, newPackInfo,
			version, randomBytes, cryptor);
		await segWriter.packing.addChain();
		return segWriter.wrap();
	}

	static async makeRestarted(
		key: Uint8Array, zerothNonce: Uint8Array, header: Uint8Array,
		version: number, randomBytes: RNG, cryptor: AsyncSBoxCryptor
	): Promise<SegmentsWriter> {
		const headerContent = await cryptor.formatWN.open(header, key);
		const segs = readSegsInfoFromHeader(headerContent);
		const segWriter = new SegWriter(
			key, zerothNonce, segs, undefined, version, randomBytes, cryptor);
		return segWriter.wrap();
	}

	static async makeUpdated(
		key: Uint8Array, zerothNonce: Uint8Array, base: ObjSource,
		version: number, randomBytes: RNG, cryptor: AsyncSBoxCryptor
	): Promise<SegmentsWriter> {
		const baseHeader = await base.readHeader();
		const headerContent = await cryptor.formatWN.open(baseHeader, key);
		const segs = readSegsInfoFromHeader(headerContent);
		const segWriter = new SegWriter(
			key, zerothNonce, segs, undefined,
			version, randomBytes, cryptor, base);
		if (segWriter.packing.index.totalSegsLen === undefined) {
			const baseSegsLen = await base.segSrc.getSize();
			if (baseSegsLen === undefined) { throw new Error(
				`Base object's source can't tell total segments' length.`); }
			segWriter.packing.turnEndlessToFinite(baseSegsLen);
		}
		return segWriter.wrap();
	}
	
	private async packSeg(
		content: Uint8Array, segId: SegId
	): Promise<Uint8Array> {
		const segInfo = this.packing.index.segmentInfo(
			segId, this.packing.segInfoExtender);
		if (!segInfo) { throw writeExc('unknownSeg'); }
		if (segInfo.type !== 'new') { throw new Error(
			`can't pack segment ${JSON.stringify(segId)}, cause it is base`); }
		if (!segInfo.needPacking) { throw writeExc('segsPacked'); }

		if (content.length !== segInfo.contentLen) {
			assert(!!segInfo.endlessChain && (content.length < segInfo.contentLen),
				`Given content has length ${content.length}, while content length of segment ${segId} should be ${segInfo.contentLen}`);
			if (!this.packing.isHeaderPacked) {
				this.packing.turnEndlessToFinite(undefined, segId, content.length);
			}
		}

		if (segInfo.headBytes) {
			const headBytes = await this.readFromBase(
				this.packing.getHeadBytesInChain(segId.chain));
			const all = new Uint8Array(headBytes.length + content.length);
			all.set(headBytes);
			all.set(content, headBytes.length);
			content = all;
		}

		const nonce = this.packing.index.segmentNonce(segId);
		const seg = await this.cryptor.pack(content, nonce, this.key);

		this.packing.markAsPacked(segId);
		return seg;
	}

	private async readFromBase(info: BaseBytesInfo): Promise<Uint8Array> {
		if (!this.base) { throw new Error(`Base source is not set in writer.`); }
		await this.base.segSrc.seek!(info.baseSeg.ofs);
		const segBytes = await this.base.segSrc.read(info.baseSeg.len);
		if (!segBytes) { throw new Error(
			`Unexpected end of base segments source`); }
		const content = await this.cryptor.open(
			segBytes, info.baseSeg.nonce, this.key);
		return content.subarray(info.ofs, info.ofs + info.len);
	};

	private destroy(): void {
		this.key.fill(0);
		this.key = (undefined as any);
	}

	private async packHeader(): Promise<Uint8Array> {
		if (this.packing.isHeaderPacked) { throw writeExc('headerPacked'); }
		// pack head
		const headContent = this.packing.getHeaderContentToPack();
		// encrypt head with a file key
		const header = await this.cryptor.formatWN.pack(
			headContent, this.headerNonce, this.key);
		return header;
	}

	wrap(): SegmentsWriter {
		const packing = this.packing;
		const wrap: SegmentsWriter = {
			locateContentOfs: pos => packing.index.locateContentOfs(pos),
			locateSegsOfs: segsOfs => packing.index.locateSegsOfs(segsOfs),
			packSeg: this.packSeg.bind(this),
			splice: (pos, rem, ins) => packing.splice(pos, rem, ins),
			packHeader: this.packHeader.bind(this),
			unpackedReencryptChainSegs: () => packing.unpackedReencryptChainSegs(),
			destroy: this.destroy.bind(this),
			get isEndlessFile() {
				return (packing.index.totalSegsLen === undefined);
			},
			get contentLength() {
				return packing.index.totalContentLen;
			},
			get segmentsLength() {
				return packing.index.totalSegsLen;
			},
			defaultSegSize: packing.index.defaultSegSize,
			version: this.version,
			segmentInfo: s => packing.index.segmentInfo(
				s, packing.segInfoExtender),
			segmentInfos: fstSeg => packing.index.segmentInfos(fstSeg,
				packing.segInfoExtender),
			get isHeaderPacked() {
				return packing.isHeaderPacked;
			},
			get areSegmentsPacked() {
				return packing.areSegmentsPacked;
			},
			showContentLayout: () => packing.showLayout(),
			showPackedLayout: () => packing.showPackedLayout(),
			setContentLength: len => packing.setContentLength(len),
			hasBase: !!this.base,
			formatVersion: this.packing.formatVersion
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}
Object.freeze(SegWriter.prototype);
Object.freeze(SegWriter);

export interface BaseBytesInfo {
	/**
	 * This identifies whole base segment.
	 */
	baseSeg: {
		ofs: number;
		contentOfs: number;
		len: number;
		nonce: Uint8Array;
	};
	/**
	 * Offset in base segment's content.
	 */
	ofs: number;
	/**
	 * Content length from base segment. Respective packed length differs by
	 * poly's length.
	 */
	len: number;
}

export type WriteExcFlag = 'segsPacked' | 'headerPacked' | 'unknownSeg' |
	'argsOutOfBounds';

export function writeExc(
	flag: WriteExcFlag, msg?: string, cause?: any
): Exception {
	const e = makeBaseException(msg, cause);
	e[flag] = true;
	return e;
}

Object.freeze(exports);