/*
 Copyright(c) 2015 - 2020 3NSoft Inc.
 
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

/**
 * This file contains code for working with file headers and (un)packing
 * file segments.
 * Exported utility should be used inside xsp library.
 */

import { calculateNonce, POLY_LENGTH, NONCE_LENGTH } from '../utils/crypt-utils';
import { assert } from '../utils/assert';

export interface SegsInfo {

	/**
	 * Common segment size before encryption. Encrypted segment is poly-bytes
	 * longer.
	 * Last segments in segment chains may be smaller than this value.
	 */
	segSize: number;

	/**
	 * Array with info objects about chains of segments with related nonces.
	 * This array shall have zero elements, if file is empty.
	 * If it is an endless file, then the last segment chain is endless.
	 */
	segChains: SegsChainInfo[];

	formatVersion: number;

}

export interface AttrSegInfo {
	nonce: Uint8Array;
	size: number;
}

export interface FiniteSegsChainInfo {
	nonce: Uint8Array;
	numOfSegs: number;
	lastSegSize: number;
	isEndless?: undefined;
}

export interface EndlessSegsChainInfo {
	nonce: Uint8Array;
	isEndless: true;
}

export type SegsChainInfo = FiniteSegsChainInfo|EndlessSegsChainInfo;

export function headerContentFor(s: SegsInfo, pads: number): Uint8Array {
	assert(Number.isInteger(pads) && (pads >= 0));
	if ((s.formatVersion === 1)
	|| (s.formatVersion === 2)) {
		return assembleV1andV2HeaderContent(s, pads);
	} else {
		throw new Error(`Version ${s.formatVersion} is not known`);
	}
}

const V_1_2_CHAIN_LEN_IN_H = 3 + 4 + NONCE_LENGTH;

function assembleV1andV2HeaderContent(s: SegsInfo, pads: number): Uint8Array {
	const headerLen = 1 + 2 + V_1_2_CHAIN_LEN_IN_H*(s.segChains.length + pads);
	const h = new Uint8Array(headerLen);
	let pos = 0;
	
	// 1) version byte
	h[pos] = s.formatVersion;
	pos += 1;

	// 3) segment size in 256 byte units
	storeUintIn2Bytes(h, pos, s.segSize >>> 8);
	pos += 2;

	// 4.1) pads: array h is already initialized to all zeros
	pos += V_1_2_CHAIN_LEN_IN_H*pads;

	// 4.2) segment chains
	for (let i=0; i<s.segChains.length; i+=1) {
		const chainInfo = s.segChains[i];
		// 4.1) number of segments in the chain
		const numOfSegs = (chainInfo.isEndless ?
			MAX_SEG_INDEX : chainInfo.numOfSegs);
		storeUintIn4Bytes(h, pos, numOfSegs);
		pos += 4;
		// 4.2) last segment size
		const lastSegSize = (chainInfo.isEndless ?
			s.segSize : chainInfo.lastSegSize);
		storeUintIn3Bytes(h, pos, lastSegSize);
		pos += 3;
		// 4.3) 1st segment nonce
		h.set(chainInfo.nonce, pos);
		pos += chainInfo.nonce.length;
	}

	return h;
}

/**
 * @param x
 * @param i
 * @return unsigned 16-bit integer (2 bytes), stored big-endian way in x,
 * starting at index i.
 */
function loadUintFrom2Bytes(x: Uint8Array, i: number): number {
	return (x[i] << 8) | x[i+1];
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 16-bit integer (2 bytes) to be stored big-endian
 * way in x, starting at index i.
 */
function storeUintIn2Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = u >>> 8;
	x[i+1] = u;
}

/**
 * @param x
 * @param i
 * @return unsigned 24-bit integer (3 bytes), stored big-endian way in x,
 * starting at index i.
 */
function loadUintFrom3Bytes(x: Uint8Array, i: number): number {
	return (x[i] << 16) | (x[i+1] << 8) | x[i+2];
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 24-bit integer (3 bytes) to be stored big-endian
 * way in x, starting at index i.
 */
function storeUintIn3Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = u >>> 16;
	x[i+1] = u >>> 8;
	x[i+2] = u;
}

/**
 * @param x
 * @param i
 * @return unsigned 32-bit integer (4 bytes), stored big-endian way in x,
 * starting at index i.
 */
export function loadUintFrom4Bytes(x: Uint8Array, i: number): number {
	// Note that (x << 24) may produce negative number, probably due to
	// treating intermediate integer as signed, and pulling sign to resulting
	// float number. Hence, we need a bit different operation here.
	return x[i]*0x1000000 + ((x[i+1] << 16) | (x[i+2] << 8) | x[i+3]);
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 32-bit integer (4 bytes) to be stored big-endian
 * way in x, starting at index i.
 */
export function storeUintIn4Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = u >>> 24;
	x[i+1] = u >>> 16;
	x[i+2] = u >>> 8;
	x[i+3] = u;
}

export function readSegsInfoFromHeader(h: Uint8Array): SegsInfo {
	if (h.length < 1) { throw inputException(``); }
	const v = h[0];
	if ((v === 1) || (v === 2)) {
		return readV1orV2Header(h);
	} else {
		throw inputException(`Given header version ${v} is not supported`);
	}
}

export interface Exception {
	runtimeException: true;
	type: 'xsp';
	msg?: string,
	cause?: any;
}

export function makeBaseException(msg?: string, cause?: any): Exception {
	return { runtimeException: true, type: 'xsp', msg, cause };
}

export type ExceptionFlag = 'inputParsing' | 'argsOutOfBounds' | 'unknownSeg' |
	'concurrentIteration';

export function exception(
	flag: ExceptionFlag, msg?: string, cause?: any
): Exception {
	const e = makeBaseException(msg, cause);
	e[flag] = true;
	return e;
}

export function inputException(msg?: string, cause?: any): Exception {
	return exception('inputParsing', msg, cause);
}

function readV1orV2Header(h: Uint8Array): SegsInfo {
	if (!isV1andV2HeaderLength(h.length)) { throw inputException(
		`Header content size ${h.length} doesn't correspond to version 1.`); }

	// 1) check version byte
	const formatVersion = h[0];
	if ((formatVersion !== 1) && (formatVersion !== 2)) { throw inputException(
		`Given header version is ${formatVersion} instead of 1 or 2`); }
	let pos = 1;

	// 3) segment size in 256 byte units
	const segSize = loadUintFrom2Bytes(h, pos) << 8;
	pos += 2;

	// 4) segment chains
	const segChains: SegsChainInfo[] = [];
	while (pos < h.length) {
		// 4.1) number of segments in the chain
		const numOfSegs = loadUintFrom4Bytes(h, pos);
		pos += 4;
		// 4.2) last segment size
		const lastSegSize = loadUintFrom3Bytes(h, pos);
		pos += 3;
		// 4.3) 1st segment nonce
		const nonce = new Uint8Array(h.subarray(pos, pos+NONCE_LENGTH));
		pos += NONCE_LENGTH;
		// distinguish between finite and endless segment chains
		let chainInfo: SegsChainInfo;
		if ((numOfSegs === MAX_SEG_INDEX) && (lastSegSize === segSize)) {
			if (pos < h.length) { throw inputException(
				`Invalid header: endless segment chain isn't the last.`); }
			chainInfo = { isEndless: true, nonce };
		} else {
			chainInfo = { numOfSegs, lastSegSize, nonce };
		}
		if (numOfSegs > 0) {
			segChains.push(chainInfo);
		}
	}

	return { segChains, segSize, formatVersion };
}

function isV1andV2HeaderLength(len: number): boolean {
	len -= (1 + 2);
	if (len < 0) { return false; }
	if ((len % 31) === 0) { return true; }
	len -= 24;
	if (len < 0) { return false; }
	return ((len % 31) === 0);
}

export interface SegId {
	chain: number;
	seg: number;
}

interface ChainLocations {
	chain: SegsChainInfo;
	content: {
		start: number;
		end?: number;
	};
	packed: {
		start: number;
		end?: number;
	};
}

export interface LocationInSegment extends SegId {
	posInSeg: number;
}

export interface SegmentInfo extends SegId {

	/**
	 * Offset of the packed segment in all of segment bytes.
	 */
	packedOfs: number;

	/**
	 * Packed segment's length. If segment chain is endless, segment can be
	 * shorter.
	 */
	packedLen: number;

	/**
	 * Offset of segment's content in all of content.
	 */
	contentOfs: number;

	/**
	 * Length of content in this segment. If segment chain is endless, segment
	 * can be shorter.
	 */
	contentLen: number;

	/**
	 * This flag's true value indicates that segment's chain is endless.
	 */
	endlessChain?: true;

}

export class Locations {

	private locations: ChainLocations[] = [];
	private variant = { num: 0 };

	constructor(
		private segs: SegsInfo
	) {
		this.update();
		Object.seal(this);
	}

	update(): void {
		this.locations = [];
		let contentOffset = 0;
		let offset = 0;
		for (let chain of this.segs.segChains) {
			let chainLocations: ChainLocations;
			if (chain.isEndless) {
				chainLocations = {
					chain,
					packed: {
						start: offset,
					},
					content: {
						start: contentOffset,
					}
				};
			} else {
				const contentLen = (chain.numOfSegs-1)*this.segs.segSize + chain.lastSegSize;
				const packedSize = contentLen + chain.numOfSegs*POLY_LENGTH;
				chainLocations = {
					chain,
					packed: {
						start: offset,
						end: offset + packedSize
					},
					content: {
						start: contentOffset,
						end: contentOffset + contentLen
					}
				};
				offset = chainLocations.packed.end!;
				contentOffset = chainLocations.content.end!;
			}
			this.locations.push(chainLocations);
		}
		this.variant.num += 1;
	}

	get defaultSegSize(): number {
		return this.segs.segSize;
	}

	get totalSegsLen(): number|undefined {
		if (this.locations.length === 0) { return 0; }
		const lastChain = this.locations[this.locations.length-1];
		return lastChain.packed.end;
	}

	get finitePartSegsLen(): number {
		const totalLen = this.totalSegsLen;
		if (typeof totalLen === 'number') { return totalLen; }
		if (this.locations.length < 2) { return 0; }
		const l = this.locations[this.locations.length-2];
		assert(!l.chain.isEndless);
		return l.packed.end!;
	}

	get totalContentLen(): number|undefined {
		if (this.locations.length === 0) { return 0; }
		const lastChain = this.locations[this.locations.length-1];
		return lastChain.content.end;
	}

	get finitePartContentLen(): number {
		const totalLen = this.totalContentLen;
		if (typeof totalLen === 'number') { return totalLen; }
		if (this.locations.length < 2) { return 0; }
		const l = this.locations[this.locations.length-2];
		assert(!l.chain.isEndless);
		return l.content.end!;
	}

	locateContentOfs(contentPosition: number): LocationInSegment {
		if (contentPosition < 0) { throw exception('argsOutOfBounds',
			"Given position is out of bounds."); }

		const chain = this.locations.findIndex(l => ((l.content.end === undefined) ? true : (l.content.end > contentPosition)));
		if (chain < 0) { throw exception('argsOutOfBounds',
			"Given position is out of bounds."); }

		const l = this.locations[chain];
		contentPosition -= l.content.start;
		const seg = Math.floor(contentPosition / this.segs.segSize);
		const posInSeg = (contentPosition - seg*this.segs.segSize);
		return { chain, seg, posInSeg };
	}

	locateSegsOfs(segsOfs: number): LocationInSegment {
		if (segsOfs < 0) { throw exception('argsOutOfBounds',
			"Given segment offset is out of bounds."); }

		const chain = this.locations.findIndex(l => ((l.packed.end === undefined) ? true : (l.packed.end > segsOfs)));
		if (chain < 0) { throw exception('argsOutOfBounds',
			"Given position is out of bounds."); }

		const l = this.locations[chain];
		segsOfs -= l.packed.start;
		const seg = Math.floor(segsOfs / (this.segs.segSize + POLY_LENGTH));
		const posInSeg = (segsOfs - seg*(this.segs.segSize + POLY_LENGTH));
		return { chain, seg, posInSeg };
	}

	getChainLocations(
		indOrChain: number|SegsChainInfo
	): ChainLocations|undefined {
		if (typeof indOrChain === 'number') {
			return this.locations[indOrChain];
		} else {
			return this.locations.find(l => (l.chain === indOrChain));
		}
	}

	segmentInfo<T extends SegmentInfo>(
		segId: SegId, infoExtender?: InfoExtender<T>
	): T {
		const l = this.locations[segId.chain];
		if (!l) { throw exception('argsOutOfBounds',
			`Chain ${segId.chain} is not found`); }
		return segmentInfo(
			segId.chain, segId.seg, l, this.segs.segSize, infoExtender);
	}

	segmentInfos<T extends SegmentInfo>(
		fstSeg?: SegId, infoExtender?: InfoExtender<T>
	): IterableIterator<T> {
		return segmentInfos(
			this.locations, this.segs.segSize, this.variant, fstSeg, infoExtender);
	}

	segmentNonce(segId: SegId): Uint8Array {
		const chain = this.segs.segChains[segId.chain];
		if (!chain) { throw exception('unknownSeg'); }
		if (chain.isEndless) {
			if (segId.seg > MAX_SEG_INDEX) { throw exception('unknownSeg'); }
			return calculateNonce(chain.nonce, segId.seg);
		} else if (segId.seg < chain.numOfSegs) {
			return calculateNonce(chain.nonce, segId.seg);
		} else {
			throw exception('unknownSeg');
		}
	}

}
Object.freeze(Locations.prototype);
Object.freeze(Locations);

export const MAX_SEG_INDEX = 0xffffffff;

export type InfoExtender<T extends SegmentInfo> =
	(chain: SegsChainInfo, segInd: number, info: T) => T;

function segmentInfo<T extends SegmentInfo>(
	chain: number, seg: number, l: ChainLocations, segSize: number,
	infoExtender?: InfoExtender<T>
): T {
	if (seg < 0) { throw exception('argsOutOfBounds',
		`Invalid segment index ${seg}`); }
	const contentOfs = l.content.start + seg*segSize;
	const packedOfs = l.packed.start + seg*(segSize+POLY_LENGTH);
	let s: SegmentInfo;
	if (l.chain.isEndless) {
		const contentLen = segSize;
		const packedLen = contentLen + POLY_LENGTH;
		s = { chain, seg,
			endlessChain: true, packedOfs, packedLen, contentOfs, contentLen };
	} else {
		if (seg >= l.chain.numOfSegs) { throw exception('argsOutOfBounds',
			`Segment ${seg} is not found`); }
		const lastSeg = (seg === (l.chain.numOfSegs-1));
		const contentLen = (lastSeg ? l.chain.lastSegSize : segSize);
		const packedLen = contentLen + POLY_LENGTH;
		s = { chain, seg, packedOfs, packedLen, contentOfs, contentLen };
	}
	return (infoExtender ? infoExtender(l.chain, seg, s as T): (s as T));
}

function* segmentInfos<T extends SegmentInfo>(
	locations: ChainLocations[], segSize: number, variant: { num: number; }, fstSeg?: SegId, infoExtender?: InfoExtender<T>
): IterableIterator<T> {
	const initVariant = variant.num;
	let fstChainInd = 0;
	let fstSegInd = 0;
	if (fstSeg) {
		fstChainInd = fstSeg.chain;
		fstSegInd = fstSeg.seg;
	}
	for (let chain=fstChainInd; chain<locations.length; chain+=1) {
		if (initVariant !== variant.num) { throw exception(
			'concurrentIteration',
			`Can't iterate cause underlying index has changed.`); }
		const l = locations[chain];
		const segIndexLimit = (l.chain.isEndless ?
			MAX_SEG_INDEX+1 : l.chain.numOfSegs);
		for (let seg=fstSegInd; seg<segIndexLimit; seg+=1) {
			if (initVariant !== variant.num) { throw exception(
				'concurrentIteration',
				`Can't iterate cause underlying index has changed.`); }
			yield segmentInfo(chain, seg, l, segSize, infoExtender);
		}
		fstSegInd = 0;
		if (l.chain.isEndless) { throw new Error(
			`Generator in endless chain is not supposed to be run till its done, and it has already run all allowed segment index values.`); }
	}
}

Object.freeze(exports);