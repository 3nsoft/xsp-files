/* Copyright(c) 2015 - 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { LocationInSegment, SegInfoHolder, SegsInfo } from './xsp-info';
import { bind } from '../binding';
import { AsyncSBoxCryptor, calculateNonce, KEY_LENGTH, NONCE_LENGTH }
	from '../crypt-utils';

export interface SegmentsWriter extends SegsInfo {
	
	/**
	 * This returns location in segment, corresponding to a given position in
	 * content.
	 * @param pos is byte's position index in file content.
	 */
	locationInSegments(pos: number): LocationInSegment;
	
	packSeg(content: Uint8Array, segInd: number):
		Promise<{ dataLen: number; seg: Uint8Array }>;
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
	/**
	 * This resets writer's internal state, keeping a file key, and removes info
	 * about segment chains, total length, etc.
	 * This allows for 100% fresh write of segments with the same file key, and
	 * same default segment size.
	 */
	reset(): Promise<void>;
	
	packHeader(): Promise<Uint8Array>;
	
	setContentLength(totalContentLen: number): void;
	
	isHeaderModified(): boolean;
	
	splice(pos: number, rem: number, ins: number);

	version: number;

}

export type RNG = (n: number) => Promise<Uint8Array>;

/**
 * This returns a promise, resolvable to segments writer.
 * @param key
 * @param zerothHeaderNonce this nonce array, advanced according to given
 * version, is used as header's nonce for this version
 * @param version
 * @param segSizein256bs is a standard segment size in 256-byte chunks
 * @param randomBytes
 * @param cryptor
 */
export async function makeSegmentsWriter(key: Uint8Array,
		zerothHeaderNonce: Uint8Array, version: number, segSizein256bs: number,
		randomBytes: RNG, cryptor: AsyncSBoxCryptor): Promise<SegmentsWriter> {
	const segWriter = new SegWriter(
		key, zerothHeaderNonce, version, randomBytes, cryptor);
	await segWriter.initClean(segSizein256bs);
	return segWriter.wrap();
}

/**
 * @param key
 * @param zerothHeaderNonce this nonce array, advanced according to given
 * version, is used as header's nonce for this version
 * @param version
 * @param baseHeader a file's header. Array must contain only header's bytes,
 * as its length is used to decide how to process it.
 * @param randomBytes
 * @param cryptor
 */
export async function makeSplicingSegmentsWriter(key: Uint8Array,
		zerothHeaderNonce: Uint8Array, version: number, baseHeader: Uint8Array,
		randomBytes: RNG, cryptor: AsyncSBoxCryptor): Promise<SegmentsWriter> {
	const segWriter = new SegWriter(
		key, zerothHeaderNonce, version, randomBytes, cryptor);
	await segWriter.initSplicing(baseHeader);
	return segWriter.wrap();
}

class SegWriter extends SegInfoHolder implements SegmentsWriter {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	
	private headerModified: boolean;

	private headerNonce: Uint8Array;
	
	/**
	 * @param key
	 * @param zerothHeaderNonce this nonce array, advanced according to given
	 * version, is used as header's nonce for this version
	 * @param version
	 * @param randomBytes
	 * @param cryptor
	 */
	constructor(key: Uint8Array,
			zerothHeaderNonce: Uint8Array,
			public version: number,
			private randomBytes: RNG,
			private cryptor: AsyncSBoxCryptor) {
		super();
		
		if (key.length !== KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);

		if (!Number.isInteger(this.version) || (this.version < 0)) {
			throw new Error(`Given version is not a non-negative integer`); }

		if (zerothHeaderNonce.length !== NONCE_LENGTH) { throw new Error(
			"Given zeroth header nonce has wrong size."); }
		this.headerNonce = ((this.version > 0) ?
			this.headerNonce = calculateNonce(zerothHeaderNonce, this.version) :
			new Uint8Array(zerothHeaderNonce));
	}

	async initClean(segSizein256bs: number): Promise<void> {
		if ((segSizein256bs < 1) || (segSizein256bs > 255)) {
			throw new Error("Given segment size is illegal.");
		}
		await this.initOfNewWriter(segSizein256bs << 8);
		this.headerModified = true;
		Object.seal(this);
	}

	async initSplicing(baseHeader: Uint8Array): Promise<void> {
		if (baseHeader.length === 65) {
			this.initForEndlessFile(
				await this.cryptor.formatWN.open(baseHeader, this.key));
		} else {
			if ((((baseHeader.length - 46) % 30) !== 0) ||
					(baseHeader.length < 46)) {
				throw new Error("Given header array has incorrect size."); }
			this.initForFiniteFile(
				await this.cryptor.formatWN.open(baseHeader, this.key));
		}
		this.headerModified = false;
		Object.seal(this);
	}

	private async initOfNewWriter(segSize: number): Promise<void> {
		this.segSize = segSize;
		this.totalContentLen = undefined;
		this.totalNumOfSegments = undefined;
		this.totalSegsLen = undefined;
		this.segChains = [ {
			numOfSegs: (undefined as any),
			lastSegSize: (undefined as any),
			nonce: await this.randomBytes(24)
		} ];
	}
	
	async packSeg(content: Uint8Array, segInd: number):
			Promise<{ dataLen: number; seg: Uint8Array }> {
		const nonce = this.getSegmentNonce(segInd);
		const expectedContentSize = this.segmentSize(segInd) - 16;
		if (content.length < expectedContentSize) {
			if (!this.isEndlessFile()) { throw new Error(
					"Given content has length "+content.length+
					", while content length of segment "+segInd+
					" should be "+expectedContentSize); }
		} else if (content.length > expectedContentSize) {
			content = content.subarray(0,expectedContentSize);
		}
		const seg = await this.cryptor.pack(content, nonce, this.key);
		nonce.fill(0);
		return { seg: seg, dataLen: content.length };
	}
	
	destroy(): void {
		this.key.fill(0);
		this.key = (undefined as any);
		for (let i=0; i < this.segChains.length; i+=1) {
			this.segChains[i].nonce.fill(0);
		}
		this.segChains = (undefined as any);
		this.cryptor = (undefined as any);
	}
	
	async reset(): Promise<void> {
		await this.initOfNewWriter(this.segSize);
		this.headerModified = true;
	}
	
	async packHeader(): Promise<Uint8Array> {
		// pack head
		let head = this.packInfoToBytes();
		// encrypt head with a file key
		head = await this.cryptor.formatWN.pack(head, this.headerNonce, this.key);
		// assemble and return complete header byte array
		this.headerModified = false;
		return head;
	}
	
	setContentLength(totalSegsLen: number): void {
		super.setContentLength(totalSegsLen);
		this.headerModified = true;
	}
	
	isHeaderModified(): boolean {
		return this.headerModified;
	}
	
	splice(pos: number, rem: number, ins: number) {
		if (this.isEndlessFile()) {
			throw new Error("Cannot splice endless file");
		}
		if (((rem < 1) && (ins < 1)) || (rem < 0) || (ins < 0)) { 
			throw new Error("Invalid modification parameters.");
		}
		if ((this.totalSegsLen! - rem + ins) > 0xffffffffffff) {
			throw new Error("Given modification will make file too long.");
		}
		const startLoc = this.locationInSegments(pos);
		
	// TODO change segments info, and return info above required
	//      (re)encryption.
		
		throw new Error("Code is incomplete");
		
		// - calculate locations of edge bytes.
		// let remEnd: LocationInSegment;
		// if (rem > 0) {
			
		// }
		
	
		// return object with info for getting bytes, and a lambda() to effect
		// the change, which should be called after reading edge bytes.
		
		// return {};
	}
	
	wrap(): SegmentsWriter {
		const wrap: SegmentsWriter = {
			locationInSegments: bind(this, this.locationInSegments),
			packSeg: bind(this, this.packSeg),
			packHeader: bind(this, this.packHeader),
			setContentLength: bind(this, this.setContentLength),
			splice: bind(this, this.splice),
			isHeaderModified: bind(this, this.isHeaderModified),
			destroy: bind(this, this.destroy),
			reset: bind(this, this.reset),
			isEndlessFile: bind(this, this.isEndlessFile),
			contentLength: bind(this, this.contentLength),
			segmentSize: bind(this, this.segmentSize),
			segmentsLength: bind(this, this.segmentsLength),
			numberOfSegments: bind(this, this.numberOfSegments),
			version: this.version
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}
Object.freeze(SegWriter.prototype);
Object.freeze(SegWriter);

Object.freeze(exports);