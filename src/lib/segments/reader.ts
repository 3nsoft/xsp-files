/*
 Copyright(c) 2015 - 2022 3NSoft Inc.
 
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

import { LocationInSegment, Locations, SegId, SegmentInfo, SegsInfo, readSegsInfoFromHeader, Exception, makeBaseException } from './xsp-info';
import { AsyncSBoxCryptor, findNonceDelta, nonceDeltaToNumber, KEY_LENGTH, NONCE_LENGTH } from '../utils/crypt-utils';
import { makeUint8ArrayCopy } from '../utils/buffer-utils';
	
export interface SegmentsReader {

	/**
	 * Is true, if this file is endless, and false, otherwise.
	 */
	readonly isEndlessFile: boolean;

	/**
	 * Number of content bytes, encrypted in this file. If file is endless,
	 * undefined is returned.
	 */
	readonly contentLength: number|undefined;

	readonly contentFiniteLength: number;

	readonly segmentsLength: number|undefined;

	segmentInfo(segId: SegId): SegmentInfo;

	segmentInfos(fstSeg?: SegId): IterableIterator<SegmentInfo>;

	readonly version: number;

	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locateContentOfs(pos: number): LocationInSegment;

	locateSegsOfs(segsOfs: number): LocationInSegment;

	canStartNumOfOpeningOps(): number;

	openSeg(segId: SegId, segBytes: Uint8Array): Promise<Uint8Array>;

	/**
	 * This wipes file key.
	 */
	destroy(): void;

	readonly formatVersion: number;

	readonly payloadFormat: number;

}

export type ValidationExcFlag = 'versionMismatch' | 'nonceMismatch';

function exception(
	flag: ValidationExcFlag, msg?: string, cause?: any
): Exception {
	const e = makeBaseException(msg, cause);
	e[flag] = true;
	return e;
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
 * @param workLabel
 */
export async function makeSegmentsReader(
	key: Uint8Array, zerothHeaderNonce: Uint8Array|undefined, version: number,
	header: Uint8Array, cryptor: AsyncSBoxCryptor, workLabel: number
): Promise<SegmentsReader> {
	if (zerothHeaderNonce) {
		const headerNonce = header.subarray(0, NONCE_LENGTH);
		const delta = findNonceDelta(zerothHeaderNonce, headerNonce);
		if (delta === undefined) { throw exception('nonceMismatch'); }
		if (version !== nonceDeltaToNumber(delta)) { throw exception(
			'versionMismatch'); }
	}
	return SegReader.makeFor(key, version, header, cryptor, workLabel);
}

class SegReader {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	private readonly index: Locations;

	private constructor(key: Uint8Array,
		private readonly segs: SegsInfo,
		public readonly version: number,
		private readonly cryptor: AsyncSBoxCryptor,
		public readonly workLabel: number
	) {
		if (key.length !== KEY_LENGTH) { throw new Error(
			"Given key has wrong size."); }
		this.key = makeUint8ArrayCopy(key);
		this.index = new Locations(this.segs);
		Object.seal(this);
	}

	static async makeFor(
		key: Uint8Array, version: number, header: Uint8Array,
		cryptor: AsyncSBoxCryptor, workLabel: number
	): Promise<SegmentsReader> {
		const headerContent = await cryptor.formatWN.open(header, key, workLabel);
		const segs = readSegsInfoFromHeader(headerContent);
		return (new SegReader(key, segs, version, cryptor, workLabel)).wrap();
	}

	private async openSeg(
		segId: SegId, segBytes: Uint8Array
	): Promise<Uint8Array> {
		const nonce = this.index.segmentNonce(segId);
		const data = await this.cryptor.open(
			segBytes, nonce, this.key, this.workLabel
		);
		return data;
	}

	private canStartNumOfOpeningOps(): number {
		return this.cryptor.canStartUnderWorkLabel(this.workLabel);
	}

	private destroy(): void {
		this.key.fill(0);
		this.key = (undefined as any);
	}

	private wrap(): SegmentsReader {
		const wrap: SegmentsReader = {
			locateContentOfs: pos => this.index.locateContentOfs(pos),
			locateSegsOfs: segsOfs => this.index.locateSegsOfs(segsOfs),
			canStartNumOfOpeningOps: this.canStartNumOfOpeningOps.bind(this),
			openSeg: this.openSeg.bind(this),
			destroy: this.destroy.bind(this),
			isEndlessFile: (this.index.totalSegsLen === undefined),
			contentLength: this.index.totalContentLen,
			segmentsLength: this.index.totalSegsLen,
			contentFiniteLength: this.index.finitePartContentLen,
			version: this.version,
			segmentInfo: s => this.index.segmentInfo(s),
			segmentInfos: fstSeg => this.index.segmentInfos(fstSeg),
			formatVersion: this.segs.formatVersion,
			payloadFormat: this.segs.payloadFormatVersion
		};
		Object.freeze(wrap);
		return wrap;
	}

}
Object.freeze(SegReader.prototype);
Object.freeze(SegReader);

Object.freeze(exports);