/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { arrays, secret_box as sbox } from 'ecma-nacl';
import { LocationInSegment, SegInfoHolder, SegsInfo } from './xsp-info';
import { bind } from '../binding';

export interface SegmentsWriter extends SegsInfo {
	
	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locationInSegments(pos: number): LocationInSegment;
	
	packSeg(content: Uint8Array, segInd: number):
		{ dataLen: number; seg: Uint8Array };
	
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
	reset(): void;
	
	packHeader(): Uint8Array;
	
	setContentLength(totalContentLen: number): void;
	
	isHeaderModified(): boolean;
	
	splice(pos: number, rem: number, ins: number);
	
}

export class SegWriter extends SegInfoHolder implements SegmentsWriter {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	
	/**
	 * This is a part of header with encrypted file key.
	 * The sole purpose of this field is to reuse these bytes on writting,
	 * eliminated a need to have a master key encryptor every time, when
	 * header is packed.
	 */
	private packedKey: Uint8Array;
	
	private arrFactory: arrays.Factory;
	
	private randomBytes: (n: number) => Uint8Array;
	
	private headerModified: boolean;
	
	/**
	 * @param key
	 * @param packedKey
	 * @param header a file's header without (!) packed key's 72 bytes.
	 * Array must contain only header's bytes, as its length is used to decide
	 * how to process it. It should be undefined for a new writer.
	 * @param segSizein256bs should be present for a new writer,
	 * otherwise, be undefined.
	 * @param randomBytes
	 * @param arrFactory
	 */
	constructor(key: Uint8Array, packedKey: Uint8Array,
			header: Uint8Array|undefined, segSizein256bs: number|undefined,
			randomBytes: (n: number) => Uint8Array, arrFactory: arrays.Factory) {
		super();
		this.arrFactory = arrFactory;
		this.randomBytes = randomBytes;
		if (key.length !== sbox.KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
		if (packedKey.length !== 72) { throw new Error(
				"Given file key pack has wrong size."); }
		this.packedKey = packedKey;
		
		if (header) {
			if (header.length === 65) {
				this.initForEndlessFile(header, this.key, this.arrFactory);
			} else {
				if ((((header.length - 46) % 30) !== 0) ||
							(header.length < 46)) { throw new Error(
						"Given header array has incorrect size."); }
				this.initForFiniteFile(header, this.key, this.arrFactory);
			}
			this.headerModified = false;
		} else if ('number' === typeof segSizein256bs) {
			if ((segSizein256bs < 1) || (segSizein256bs > 255)) {
				throw new Error("Given segment size is illegal.");
			}
			this.initOfNewWriter(segSizein256bs << 8);
			this.headerModified = true;
		} else {
			throw new Error("Arguments are illegal, both header bytes and "+
					"segment size are missing");
		}
		Object.seal(this);
	}
	
	private initOfNewWriter(segSize: number): void {
		this.segSize = segSize;
		this.totalContentLen = undefined;
		this.totalNumOfSegments = undefined;
		this.totalSegsLen = undefined;
		this.segChains = [ {
			numOfSegs: (undefined as any),
			lastSegSize: (undefined as any),
			nonce: this.randomBytes(24)
		} ];
	}
	
	packSeg(content: Uint8Array, segInd: number):
			{ dataLen: number; seg: Uint8Array } {
		var nonce = this.getSegmentNonce(segInd, this.arrFactory);
		var expectedContentSize = this.segmentSize(segInd) - 16;
		if (content.length < expectedContentSize) {
			if (!this.isEndlessFile()) { throw new Error(
					"Given content has length "+content.length+
					", while content length of segment "+segInd+
					" should be "+expectedContentSize); }
		} else if (content.length > expectedContentSize) {
			content = content.subarray(0,expectedContentSize);
		}
		var seg = sbox.pack(content, nonce, this.key, this.arrFactory);
		this.arrFactory.recycle(nonce);
		this.arrFactory.wipeRecycled();
		return { seg: seg, dataLen: content.length };
	}
	
	destroy(): void {
		this.arrFactory.wipe(this.key);
		this.key = (undefined as any);
		for (var i=0; i < this.segChains.length; i+=1) {
			this.arrFactory.wipe(this.segChains[i].nonce);
		}
		this.segChains = (undefined as any);
		this.arrFactory = (undefined as any);
	}
	
	reset(): void {
		this.initOfNewWriter(this.segSize);
		this.headerModified = true;
	}
	
	packHeader(): Uint8Array {
		// pack head
		var head = this.packInfoToBytes();
		// encrypt head with a file key
		head = sbox.formatWN.pack(head, this.randomBytes(24),
				this.key, this.arrFactory);
		// assemble and return complete header byte array
		var completeHeader = new Uint8Array(
				this.packedKey.length + head.length);
		completeHeader.set(this.packedKey, 0);
		completeHeader.set(head, 72);
		this.headerModified = false;
		return completeHeader;
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
		if ((this.totalSegsLen - rem + ins) > 0xffffffffffff) {
			throw new Error("Given modification will make file too long.");
		}
		var startLoc = this.locationInSegments(pos);
		
	// TODO change segments info, and return info above required
	//      (re)encryption.
		
		throw new Error("Code is incomplete");
		
		// - calculate locations of edge bytes.
		var remEnd: LocationInSegment;
		if (rem > 0) {
			
		}
		
	
		// return object with info for getting bytes, and a lambda() to effect
		// the change, which should be called after reading edge bytes.
		
		return {};
	}
	
	wrap(): SegmentsWriter {
		var wrap: SegmentsWriter = {
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
			numberOfSegments: bind(this, this.numberOfSegments)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}
Object.freeze(SegWriter.prototype);
Object.freeze(SegWriter);

Object.freeze(exports);