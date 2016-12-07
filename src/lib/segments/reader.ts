/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { arrays, secret_box as sbox } from 'ecma-nacl';
import { LocationInSegment, SegInfoHolder, SegsInfo } from './xsp-info';
import { bind } from '../binding';

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
		{ data: Uint8Array; segLen: number; last?: boolean; };
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
}

export class SegReader extends SegInfoHolder implements SegmentsReader {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	
	private arrFactory: arrays.Factory;
	
	constructor(key: Uint8Array, header: Uint8Array,
			arrFactory: arrays.Factory) {
		super();
		this.arrFactory = arrFactory;
		if (key.length !== sbox.KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
		if (header.length === 65) {
			this.initForEndlessFile(header, this.key, this.arrFactory);
		} else {
			if ((((header.length - 46) % 30) !== 0) ||
						(header.length < 46)) { throw new Error(
					"Given header array has incorrect size."); }
			this.initForFiniteFile(header, this.key, this.arrFactory);
		}
		Object.seal(this);
	}
	
	openSeg(seg: Uint8Array, segInd: number):
			{ data: Uint8Array; segLen: number; last?: boolean; } {
		var isLastSeg = ((segInd + 1) === this.totalNumOfSegments);
		var nonce = this.getSegmentNonce(segInd, this.arrFactory);
		var segLen = this.segmentSize(segInd);
		if (seg.length < segLen) {
			if (this.isEndlessFile()) {
				isLastSeg = true;
			} else {
				throw new Error("Given byte array is smaller than segment's size.");
			}
		} else if (seg.length > segLen) {
			seg = seg.subarray(0, segLen);
		}
		var bytes = sbox.open(seg, nonce, this.key, this.arrFactory);
		this.arrFactory.recycle(nonce);
		this.arrFactory.wipeRecycled();
		return { data: bytes, segLen: segLen, last: isLastSeg };
	}
	
	destroy(): void {
		this.arrFactory.wipe(this.key);
		this.key = (undefined as any);
		for (var i=0; i<this.segChains.length; i+=1) {
			this.arrFactory.wipe(this.segChains[i].nonce);
		}
		this.segChains = (undefined as any);
		this.arrFactory = (undefined as any);
	}
	
	wrap(): SegmentsReader {
		var wrap: SegmentsReader = {
			locationInSegments: bind(this, this.locationInSegments),
			openSeg: bind(this, this.openSeg),
			destroy: bind(this, this.destroy),
			isEndlessFile: bind(this, this.isEndlessFile),
			contentLength: bind(this, this.contentLength),
			segmentSize: bind(this, this.segmentSize),
			segmentsLength: bind(this, this.segmentsLength),
			numberOfSegments: bind(this, this.numberOfSegments)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}
Object.freeze(SegReader.prototype);
Object.freeze(SegReader);

Object.freeze(exports);