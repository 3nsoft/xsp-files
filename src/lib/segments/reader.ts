/* Copyright(c) 2015 - 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { LocationInSegment, SegInfoHolder, SegsInfo } from './xsp-info';
import { bind } from '../binding';
import { AsyncSBoxCryptor, findNonceDelta, nonceDeltaToNumber,
	KEY_LENGTH, NONCE_LENGTH }
	from '../crypt-utils';
	
export interface SegmentsReader extends SegsInfo {
	
	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locationInSegments(pos: number): LocationInSegment;
	
	/**
	 * @param seg is an array with encrypted segment's bytes, starting at
	 * zeroth index. Array may be longer than a segment, but it will an error,
	 * if it is shorter.
	 * @param segInd is segment's index in file.
	 * @return decrypted content bytes of a given segment and a length of
	 * decrypted segment.
	 * Data array is a view of buffer, which has 32 zeros preceding
	 * content bytes.
	 */
	openSeg(seg: Uint8Array, segInd: number):
		Promise<{ data: Uint8Array; segLen: number; last?: boolean; }>;
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;

	version: number;

}

/**
 * This returns a promise, resolvable to segments reader.
 * @param key 
 * @param zerothHeaderNonce is a zeroth version header nonce. When nonce is
 * given, header will be checked to have nonce that corresponds to given
 * version. If undefined is given, version check is not performed.
 * @param version 
 * @param header is object's header, from which reader's parameters are
 * initialized.
 * @param cryptor 
 */
export async function makeSegmentsReader(key: Uint8Array,
		zerothHeaderNonce: Uint8Array|undefined, version: number,
		header: Uint8Array, cryptor: AsyncSBoxCryptor): Promise<SegmentsReader> {
	if (zerothHeaderNonce) {
		const headerNonce = header.subarray(0, NONCE_LENGTH);
		const delta = findNonceDelta(zerothHeaderNonce, headerNonce);
		if ((delta === undefined) || (version !== nonceDeltaToNumber(delta))) {
			throw new Error("Header's version check failed");
		}
	}
	const segsReader = new SegReader(key, version, cryptor);
	await segsReader.init(header);
	return segsReader.wrap();
}

class SegReader extends SegInfoHolder implements SegmentsReader {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	key: Uint8Array;

	constructor(key: Uint8Array,
			public version: number,
			private cryptor: AsyncSBoxCryptor) {
		super();
		if (key.length !== KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
	}

	async init(header: Uint8Array): Promise<void> {
		if (header.length === 65) {
			this.initForEndlessFile(
				await this.cryptor.formatWN.open(header, this.key));
		} else {
			if ((((header.length - 46) % 30) !== 0) || (header.length < 46)) {
				throw new Error("Given header array has incorrect size."); }
			this.initForFiniteFile(
				await this.cryptor.formatWN.open(header, this.key));
		}
		Object.seal(this);
	}
	
	async openSeg(seg: Uint8Array, segInd: number):
			Promise<{ data: Uint8Array; segLen: number; last?: boolean; }> {
		let isLastSeg = ((segInd + 1) === this.totalNumOfSegments);
		const nonce = this.getSegmentNonce(segInd);
		const segLen = this.segmentSize(segInd);
		if (seg.length < segLen) {
			if (this.isEndlessFile()) {
				isLastSeg = true;
			} else {
				throw new Error("Given byte array is smaller than segment's size.");
			}
		} else if (seg.length > segLen) {
			seg = seg.subarray(0, segLen);
		}
		const bytes = await this.cryptor.open(seg, nonce, this.key);
		nonce.fill(0);
		return { data: bytes, segLen: segLen, last: isLastSeg };
	}
	
	destroy(): void {
		this.key.fill(0);
		this.key = (undefined as any);
		for (let i=0; i<this.segChains.length; i+=1) {
			this.segChains[i].nonce.fill(0);
		}
		this.segChains = (undefined as any);
		this.cryptor = (undefined as any);
	}
	
	wrap(): SegmentsReader {
		const wrap: SegmentsReader = {
			locationInSegments: bind(this, this.locationInSegments),
			openSeg: bind(this, this.openSeg),
			destroy: bind(this, this.destroy),
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
Object.freeze(SegReader.prototype);
Object.freeze(SegReader);

Object.freeze(exports);