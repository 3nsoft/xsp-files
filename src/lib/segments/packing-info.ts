/*
 Copyright(c) 2018 - 2019 3NSoft Inc.
 
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

import { SegId, Locations, SegsInfo, headerContentFor, SegsChainInfo,
	FiniteSegsChainInfo, InfoExtender }
	from './xsp-info';
import { calculateNonce, NONCE_LENGTH } from '../utils/crypt-utils';
import { Layout, LayoutBaseSection, LayoutNewSection } from '../streaming/common';
import { POLY_LENGTH } from 'ecma-nacl/dist/lib/boxes/secret_box';
import { assert } from '../utils/assert';
import { copy } from '../utils/json-utils';
import { RNG, BaseBytesInfo, WritableSegmentInfo, NewSegmentInfo, BaseSegmentInfo, writeExc } from './writer';
import { NewSegments } from './new-segments';

type NewSegsChainInfo = SegsChainInfo & {
	type: 'new';
	headBytes?: BaseBytesInfo;
	newSegs: NewSegments;
};
type BaseSegsChainInfo = FiniteSegsChainInfo & {
	type: 'base';
	baseOfs: number;
	baseContentOfs: number;
}
type WritableSegsChainInfo = NewSegsChainInfo | BaseSegsChainInfo;

interface WritableSegsInfo extends SegsInfo {
	segChains: WritableSegsChainInfo[];
}

/**
 * This is a packing tracking logic and structures, used in segements' writer.
 */
export class PackingInfo {

	/**
	 * This flag indicates if header has been packed. No changes are allowed to
	 * segments' geometry when header has already been packed.
	 */
	private headerPacked = false;

	private segs: WritableSegsInfo;
	index: Locations;

	private constructor(
		baseSegsOrSegSize: SegsInfo|number,
		private readonly baseVersion: number|undefined,
		private readonly randomBytes: RNG
	) {
		if (typeof baseSegsOrSegSize === 'number') {
			this.segs = {
				segSize: baseSegsOrSegSize,
				segChains: [],
			};
			this.index = new Locations(this.segs);
		} else {
			this.segs = baseSegsOrSegSize as any;
			this.index = new Locations(this.segs);
			for (let i=0; i<this.segs.segChains.length; i+=1) {
				const chain = this.segs.segChains[i] as BaseSegsChainInfo;
				chain.type = 'base';
				const l = this.index.getChainLocations(i);
				if (!l) { throw new Error(
					`Missing location in index that matches current chain`); }
				chain.baseOfs = l.packed.start;
				chain.baseContentOfs = l.content.start;
			}
		}
		Object.seal(this);
	}

	static make(baseSegsOrSegSize: SegsInfo|number, randomBytes: RNG,
			baseVer?: number): PackingInfo {
		return new PackingInfo(baseSegsOrSegSize, baseVer, randomBytes);
	}

	static restartWithAllNewFrozenLayout(segs: SegsInfo): PackingInfo {
		const pInfo = new PackingInfo(segs.segSize, undefined, undefined as any);
		pInfo.initWithAllNewFrozenLayout(segs);
		return pInfo;
	}

	private initWithAllNewFrozenLayout(segs: SegsInfo): void {
		this.segs = {
			segSize: segs.segSize,
			segChains: segs.segChains as any,
		};
		this.index = new Locations(this.segs);
		for (let i=0; i<this.segs.segChains.length; i+=1) {
			const chain = this.segs.segChains[i] as NewSegsChainInfo;
			chain.type = 'new';
			chain.newSegs = new NewSegments(chain)
		}
		this.headerPacked = true;
	}

	showLayout(): Layout {
		const layout: Layout = { sections: [] };
		let prevSec: LayoutBaseSection|LayoutNewSection|undefined = undefined;
		for (let i=0; i<this.segs.segChains.length; i+=1) {
			const chain = this.segs.segChains[i];
			const l = this.index.getChainLocations(i)!;
			if (chain.type === 'base') {
				const baseSec: LayoutBaseSection = {
					src: 'base',
					baseOfs: chain.baseContentOfs,
					ofs: l.content.start,
					len: l.content.end! - l.content.start
				};
				if (prevSec && (prevSec.src === 'base')
				&& ((prevSec.baseOfs+prevSec.len) === baseSec.baseOfs)) {
					prevSec.len += baseSec.len;
				} else {
					layout.sections.push(baseSec);
					prevSec = baseSec;
				}
			} else if (chain.type === 'new') {
				if (chain.headBytes) {
					const headBytesSec: LayoutBaseSection = {
						src: 'base',
						ofs: l.content.start - chain.headBytes.len,
						len: chain.headBytes.len,
						baseOfs:
							chain.headBytes.baseSeg.contentOfs + chain.headBytes.ofs
					};
					if (prevSec && (prevSec.src === 'base')
					&& ((prevSec.baseOfs+prevSec.len) === headBytesSec.baseOfs)) {
						prevSec.len += headBytesSec.len;
					} else {
						layout.sections.push(headBytesSec);
						prevSec = headBytesSec;
					}
				}

				const newSec: LayoutNewSection = {
					src: 'new',
					ofs: l.content.start,
					len: ((l.content.end === undefined) ?
						undefined : l.content.end - l.content.start)
				};
				if (prevSec && (prevSec.src === 'new')) {
					prevSec.len = ((newSec.len === undefined) ?
						undefined : (prevSec.len! + newSec.len));
				} else {
					layout.sections.push(newSec);
					prevSec = newSec;
				}
			} else {
				throw new Error(`Unexpected segment chain type`);
			}
		}

		if (layout.sections.find(s => (s.src === 'base'))) {
			layout.base = this.baseVersion;
		}
		return layout;
	}

	showPackedLayout(): Layout {
		const layout: Layout = { sections: [] };
		let prevSec: LayoutBaseSection|LayoutNewSection|undefined = undefined;
		for (let i=0; i<this.segs.segChains.length; i+=1) {
			const chain = this.segs.segChains[i];
			const l = this.index.getChainLocations(i)!;
			if (chain.type === 'base') {
				const baseSec: LayoutBaseSection = {
					src: 'base',
					baseOfs: chain.baseOfs,
					ofs: l.packed.start,
					len: l.packed.end! - l.packed.start
				};
				if (prevSec && (prevSec.src === 'base')
				&& ((prevSec.baseOfs+prevSec.len) === baseSec.baseOfs)) {
					prevSec.len += baseSec.len;
				} else {
					layout.sections.push(baseSec);
					prevSec = baseSec;
				}
			} else if (chain.type === 'new') {
				const newSec: LayoutNewSection = {
					src: 'new',
					ofs: l.packed.start,
					len: ((l.packed.end === undefined) ?
						undefined : l.packed.end - l.packed.start)
				};
				if (prevSec && (prevSec.src === 'new')) {
					prevSec.len = ((newSec.len === undefined) ?
						undefined : (prevSec.len! + newSec.len));
				} else {
					layout.sections.push(newSec);
					prevSec = newSec;
				}
			} else {
				throw new Error(`Unexpected segment chain type`);
			}
		}

		if (layout.sections.find(s => (s.src === 'base'))) {
			layout.base = this.baseVersion;
		}
		return layout;
	}

	private getChain(chainInd: number): WritableSegsChainInfo {
		const chain = this.segs.segChains[chainInd];
		if (!chain) { throw new Error(`Unknown chain index ${chainInd}`); }
		return chain;
	}

	segInfoExtender: InfoExtender<WritableSegmentInfo> =
			(c: WritableSegsChainInfo, segInd, s) => {
		s.type = c.type;
		if (c.type === 'new') {
			(s as NewSegmentInfo).needPacking = c.newSegs.isSegUnpacked(segInd);
			if ((segInd === 0) && c.headBytes) {
				(s as NewSegmentInfo).headBytes = c.headBytes.len;
				s.contentLen -= (s as NewSegmentInfo).headBytes!;
			}
		} else if (c.type === 'base') {
			(s as BaseSegmentInfo).baseOfs =
				c.baseOfs + segInd*(this.segs.segSize+POLY_LENGTH);
			(s as BaseSegmentInfo).baseContentOfs =
				c.baseContentOfs + segInd*this.segs.segSize;
		}
		return s;
	}

	private ensureGeomNotLocked(): void {
		assert(!this.headerPacked,
			`Geometry of segments can't be changed cause header has already been packed.`);
	}

	turnEndlessToFinite(packedSegsLen: number|undefined,
			lastSegId?: SegId, lastSegLen?: number): void {
		this.ensureGeomNotLocked();

		const lastInd = this.segs.segChains.length - 1;
		if (typeof packedSegsLen === 'number') {
			// calculate lastSegId and lastSegLen for a given packed length
			const s = this.index.getChainLocations(lastInd);
			if (!s) { throw new Error(
				`Missing chain ${lastInd} in current location index`); }

			let lastChainPackedLen = packedSegsLen - s.packed.start;
			assert(lastChainPackedLen >= 0);
			
			const packedSegSize = this.segs.segSize + POLY_LENGTH;
			const segsFraction = lastChainPackedLen / packedSegSize;
			const lastSegIsOdd = (segsFraction % 1 > 0);
			const numOfSegs = Math.floor(segsFraction) + (lastSegIsOdd ? 1 : 0);

			lastSegId = {
				chain: lastInd,
				seg: numOfSegs-1
			};
			lastSegLen = (lastSegIsOdd ?
				lastChainPackedLen - (numOfSegs-1)*packedSegSize - POLY_LENGTH :
				this.segs.segSize);
		} else if (!lastSegId || (lastSegLen === undefined)) {
			throw new Error(
				`Bad arguments given in absence of total length, las t segement ${lastSegId}, last segment length ${lastSegLen}`);
		}

		if (lastSegId.chain !== lastInd) { throw new Error(
			`Can't change chain ${lastSegId.chain} if last chain index is ${lastInd}`); }
		const last = this.getChain(lastSegId.chain);
		assert(!!last.isEndless, `This method should be called on endless`);

		delete last.isEndless;
		(last as FiniteSegsChainInfo).numOfSegs = lastSegId.seg + 1;
		(last as FiniteSegsChainInfo).lastSegSize = lastSegLen;

		this.index.update();
	}

	async setContentLength(contentLen: number|undefined): Promise<void> {
		this.ensureGeomNotLocked();

		if (contentLen === undefined) {
			if (this.index.totalContentLen === undefined) { return; }
			await this.addChain();
			return;
		}

		assert(Number.isInteger(contentLen) && (contentLen >= 0),
			`Given invalid file content length ${contentLen}`);

		if (contentLen === 0) {
			ensureCanDropChains(this.segs.segChains);
			this.segs.segChains = [];
			this.index.update();
			return;
		}

		const initLen = this.index.totalContentLen;

		if (initLen !== undefined) {
			if (contentLen > initLen) {
				await this.growFileBy(contentLen - initLen);
				return;
			} else if (contentLen === initLen) {
				return;
			}
		}

		await this.cutFileTo(contentLen);
	}

	private async growFileBy(delta: number): Promise<void> {
		assert(delta > 0, `Invalid amount to grow file: ${delta}`);
		const lastChain = ((this.segs.segChains.length > 0) ?
			this.getChain(this.segs.segChains.length-1) : undefined);
	
		if (lastChain) {
			assert(!lastChain.isEndless,
				`Trying to grow an endless segment chain.`);
			if ((lastChain.type === 'new') && lastChain.newSegs.canGrowTail()) {
				this.growChainTail(lastChain, delta);
			} else {
				await this.addChain(delta);
			}
		} else {
			await this.addChain(delta);
		}
	}

	private async cutFileTo(contentLen: number): Promise<void> {
		const end = this.index.locateContentOfs(contentLen);
		if ((end.seg === 0) && (end.posInSeg === 0)) {
			this.dropChains(this.segs.segChains.slice(end.chain));
			this.index.update();
		} else {
			const edge = await this.cutChainTail(
				this.getChain(end.chain), end.seg, end.posInSeg);
			this.dropChains(edge ?
				this.segs.segChains.slice(this.getChainIndex(edge) + 1) :
				this.segs.segChains.slice(end.chain + 1));
			this.index.update();
		}
	}

	private getChainIndex(c: WritableSegsChainInfo): number {
		const cInd = this.segs.segChains.indexOf(c);
		if (cInd < 0) { throw new Error(`Given segment chain is not found`); }
		return cInd;
	}

	private async cutChainHead(c: WritableSegsChainInfo, seg: number,
			posInSeg: number): Promise<NewSegsChainInfo|undefined> {
		if ((seg === 0) && (posInSeg === 0)) { return; }

		if (c.type === 'new') {
			if (!c.newSegs.noSegsPacked) { throw writeExc(
				'segsPacked', `Can't cut head of a new segment chain`); }
			// cutting of endless chain doesn't change its size, and
			// a head cut can be turned into tail cut
			if (!c.isEndless) {
				const newChainLen = (c.numOfSegs - 1)*this.segs.segSize +
					c.lastSegSize - seg*this.segs.segSize - posInSeg;
				const rightSeg = Math.floor(newChainLen/this.segs.segSize);
				const rightPos = newChainLen - rightSeg*this.segs.segSize;
				await this.cutChainTail(c, rightSeg, rightPos);
			}
			return;
		}

		if (seg > 0) {
			c.numOfSegs -= seg;
			c.baseOfs += seg*(this.segs.segSize + POLY_LENGTH);
			c.baseContentOfs += seg*this.segs.segSize;
			c.nonce = calculateNonce(c.nonce, seg);
		}
		const cutSeg = (posInSeg !== 0);
		return (cutSeg ?
			await this.cutEdgeSegmentOf(c, posInSeg, true) :
			undefined);
	}

	private async cutChainMiddle(c: WritableSegsChainInfo, leftSeg: number,
			leftPos: number, rightSeg: number, rightPos: number): Promise<{
				left: WritableSegsChainInfo; right: WritableSegsChainInfo; }> {
		if (c.type === 'new') {
			// instead of actually cut the middle, we do check that ensures no
			// writes done in a cut section and to the right of it, and we
			if (!c.newSegs.canCutTail(leftSeg, false)) { throw writeExc(
				'segsPacked', `Can't cut middle of a new segment chain`); }
			if (c.headBytes && (leftSeg === 0) && (leftPos < c.headBytes.len)) {
				c.headBytes.len = leftPos;
			}
			if (!c.isEndless
			&& ((leftSeg !== rightSeg) || (leftPos !== rightPos))) {
				// XXX calculate proper cut position as tot_len - middle_len
				await this.cutChainTail(c, rightSeg, rightPos);
			}
			const left = c;
			const right = left;
			return { left, right };
		}

		const c2 = copy(c);
		const cInd = this.getChainIndex(c);
		this.segs.segChains.splice(cInd+1, 0, c2);
		const leftReecrypt = await this.cutChainTail(c, leftSeg, leftPos);
		const rightReencrypt = await this.cutChainHead(c2, rightSeg, rightPos);
		const left = (leftReecrypt ? leftReecrypt : c);
		const right = (rightReencrypt ? rightReencrypt : c2);
		return { left, right };
	}

	private async cutChainTail(c: WritableSegsChainInfo, endSeg: number,
			endPosInSeg: number): Promise<NewSegsChainInfo|undefined> {
		const cutSeg = (endPosInSeg !== 0);
		const numOfSegs = endSeg + (cutSeg ? 1 : 0);

		if (c.type === 'new') {
			if (!cutSeg) {
				endSeg -= 1;
			}
			c.newSegs.cutTail(endSeg, cutSeg);
			if ((endSeg === 0) && c.headBytes) {
				if (endPosInSeg <= c.headBytes.len) {
					c.headBytes.len = endPosInSeg;
				}
			}
			if (c.isEndless) {
				delete c.isEndless;
			}
			(c as FiniteSegsChainInfo).numOfSegs = numOfSegs;
			(c as FiniteSegsChainInfo).lastSegSize = (cutSeg ? endPosInSeg : this.segs.segSize);
			return;
		}

		if (numOfSegs < c.numOfSegs) {
			c.numOfSegs = numOfSegs;
			c.lastSegSize = this.segs.segSize;
		}
		return (cutSeg ?
			await this.cutEdgeSegmentOf(c, endPosInSeg, false) :
			undefined);
	}

	private async cutEdgeSegmentOf(c: BaseSegsChainInfo,
			posInSeg: number, atHead: boolean):
			Promise<NewSegsChainInfo|undefined> {
		if (c.numOfSegs === 1) {
			const headBytes: BaseBytesInfo = {
				baseSeg: {
					ofs: c.baseOfs,
					contentOfs: c.baseContentOfs,
					len: c.lastSegSize+POLY_LENGTH,
					nonce: c.nonce
				},
				len: undefined as any,
				ofs: undefined as any
			};
			if (atHead) {
				headBytes.ofs = posInSeg;
				headBytes.len = c.lastSegSize - posInSeg;
			} else {
				headBytes.ofs = 0;
				headBytes.len = posInSeg;
			}

			delete c.baseOfs;
			delete c.baseContentOfs;
			(c as any as NewSegsChainInfo).type = 'new';
			(c as any as NewSegsChainInfo).headBytes = headBytes;
			c.lastSegSize = headBytes.len;
			c.nonce = await this.randomBytes(NONCE_LENGTH);
			(c as any as NewSegsChainInfo).newSegs = new NewSegments(c);
			return c as any as NewSegsChainInfo;
		}

		if (atHead) {
			const headBytes: BaseBytesInfo = {
				baseSeg: {
					ofs: c.baseOfs,
					contentOfs: c.baseContentOfs,
					len: this.segs.segSize+POLY_LENGTH,
					nonce: c.nonce
				},
				len: this.segs.segSize - posInSeg,
				ofs: posInSeg
			};

			const edge: NewSegsChainInfo = {
				nonce: await this.randomBytes(NONCE_LENGTH),
				numOfSegs: 1,
				lastSegSize: this.segs.segSize - posInSeg,
				type: 'new',
				newSegs: undefined as any,
				headBytes
			};
			edge.newSegs = new NewSegments(edge);

			c.nonce = calculateNonce(c.nonce, 1);
			c.baseOfs += this.segs.segSize + POLY_LENGTH;
			c.baseContentOfs += this.segs.segSize;
			c.numOfSegs -= 1;
			const cInd = this.getChainIndex(c);
			this.segs.segChains.splice(cInd, 0, edge);
			return edge;
		} else {
			const headBytes: BaseBytesInfo = {
				baseSeg: {
					ofs: c.baseOfs + (c.numOfSegs-1)*(this.segs.segSize+POLY_LENGTH),
					contentOfs: c.baseOfs + (c.numOfSegs-1)*this.segs.segSize,
					len: c.lastSegSize+POLY_LENGTH,
					nonce: calculateNonce(c.nonce, c.numOfSegs-1)
				},
				len: posInSeg,
				ofs: 0
			};

			const edge: NewSegsChainInfo = {
				nonce: await this.randomBytes(NONCE_LENGTH),
				numOfSegs: 1,
				lastSegSize: posInSeg,
				type: 'new',
				newSegs: undefined as any,
				headBytes
			};
			edge.newSegs = new NewSegments(edge);

			c.numOfSegs -= 1;
			c.lastSegSize = this.segs.segSize;
			const cInd = this.getChainIndex(c);
			this.segs.segChains.splice(cInd+1, 0, edge);
			return edge;
		}
	}

	getHeadBytesInChain(i: number): BaseBytesInfo {
		const chain = this.getChain(i) as NewSegsChainInfo;
		if (!chain.headBytes) { throw new Error(
			`Chain info doesn't have header bytes information`); }
		return chain.headBytes;
	}

	async addChain(contentLen?: number, chainInd?: number, updateIndex = true):
			Promise<void> {
		this.ensureGeomNotLocked();
		
		if (chainInd === undefined) {
			chainInd = this.segs.segChains.length;
		}
		assert(Number.isInteger(chainInd) && (chainInd >= 0)
			&& (chainInd <= this.segs.segChains.length),
			`Chain index ${chainInd} is out of bounds.`);

		let chain: NewSegsChainInfo;
		if (contentLen === undefined) {
			if (this.segs.segChains.length > 0) {
				assert(chainInd === this.segs.segChains.length,
					`Can't add endless chain between other chains.`);
				const last = this.getChain(this.segs.segChains.length-1);
				assert(!last.isEndless, `Can't add second endless chain.`);
			}
			chain = {
				isEndless: true,
				nonce: await this.randomBytes(NONCE_LENGTH),
				type: 'new',
				newSegs: undefined as any
			};
		} else {
			if ((chainInd === this.segs.segChains.length) && (chainInd > 0)) {
				const last = this.getChain(chainInd-1);
				assert(!last.isEndless,
					`Can't add a chain after an existing endless chain.`);
			}
			const { numOfSegs, lastSegSize } = chainSizeForContent(
				contentLen, this.segs.segSize);
			chain = {
				nonce: await this.randomBytes(NONCE_LENGTH),
				numOfSegs,
				lastSegSize,
				type: 'new',
				newSegs: undefined as any
			};
		}
		chain.newSegs = new NewSegments(chain);

		this.segs.segChains.splice(chainInd, 0, chain);
		if (updateIndex) {
			this.index.update();
		}
	}

	private dropChains(toDrop: WritableSegsChainInfo[]): void {
		for (const c of toDrop) {
			const chainInd = this.segs.segChains.indexOf(c);
			if (chainInd >= 0) {
				this.segs.segChains.splice(chainInd, 1);
			}
		}
	}

	private growChainTail(c: NewSegsChainInfo, delta: number,
			updateIndex = true): void {
		if (c.isEndless) { throw new Error(
			`This method should be called for finite segment chains`); }
		const newContentInChain =
			this.segs.segSize*(c.numOfSegs - 1) +
			c.lastSegSize +
			delta;
		const { numOfSegs, lastSegSize } = chainSizeForContent(
			newContentInChain, this.segs.segSize);
		c.newSegs.growTail(numOfSegs-1);
		c.numOfSegs = numOfSegs;
		c.lastSegSize = lastSegSize;
		if (updateIndex) {
			this.index.update();
		}
	}

	async splice(pos: number, rem: number, ins: number): Promise<void> {
		this.ensureGeomNotLocked();
		assert(Number.isInteger(pos) && (pos >= 0) && Number.isInteger(rem)
			&& (rem >= 0) && Number.isInteger(ins) && (ins >= 0),
			`Bad arg value(s) given: pos = ${pos} rem = ${rem}, ins = ${ins}`);

		// noop combination
		if ((rem === 0) && (ins === 0)) { return; }

		// file cut-n-grow combinations
		if (this.index.totalContentLen !== undefined) {
			if (pos > this.index.totalContentLen) {
				throw new Error(
					`Given position ${pos} is greater than content length ${this.index.totalContentLen}`);
			} else if (pos === this.index.totalContentLen) {
				if (ins > 0) {
					await this.growFileBy(ins);
				}
				return;
			} else if ((pos + rem) >= this.index.totalContentLen) {
				await this.cutFileTo(pos);
				if (ins > 0) {
					await this.growFileBy(ins);
				}
			}
		}

		const { left, right } = await this.cutForInsert(pos, rem);

		if (ins > 0) {
			if (left === right) {
				// this is a no-cut situation, cause it is not needed
				if (left.type !== 'new') { throw new Error(
					`Not a new chain in a no-cut situation`); }
				if (!left.isEndless) {
					this.growChainTail(left, ins, false);
				} // else do nothing
			} else if (left && (left.type === 'new')) {
				this.growChainTail(left, ins, false);
			} else if (left) {
				await this.addChain(ins, this.getChainIndex(left) + 1, false);
			} else {
				await this.addChain(ins, 0, false);
			}
		}

		this.index.update();
	}

	private async cutForInsert(pos: number, rem: number):
			Promise<{ left?: WritableSegsChainInfo;
				right: WritableSegsChainInfo; }> {
		const leftCut = this.index.locateContentOfs(pos);
		const leftCutIsBetweenChains =
			((leftCut.seg === 0) && (leftCut.posInSeg === 0));
		
		// no removal and cut between two chains
		if ((rem === 0) && leftCutIsBetweenChains) {
			const left = ((leftCut.chain === 0) ?
				undefined : this.getChain(leftCut.chain - 1));
			const right = this.getChain(leftCut.chain);
			return { left, right };
		}

		const rightCut = ((rem === 0) ?
			leftCut : this.index.locateContentOfs(pos + rem));

		// left cut happens between chains
		if (leftCutIsBetweenChains) {
			const chainsToDrop = ensureCanDropChains(
				this.segs.segChains.slice(leftCut.chain, rightCut.chain));
			const c = this.getChain(leftCut.chain);
			const reencrypted = await this.cutChainHead(
				c, rightCut.seg, rightCut.posInSeg); // noop for seg=0 & posInSeg=0
			this.dropChains(chainsToDrop);
			const left = ((leftCut.chain === 0) ?
				undefined : this.getChain(leftCut.chain - 1));
			const right = (reencrypted ?
				reencrypted : this.getChain(rightCut.chain));
			return { left, right };
		}
		
		if (leftCut.chain === rightCut.chain) {
			const c = this.getChain(leftCut.chain);
			return await this.cutChainMiddle(
				c, leftCut.seg, leftCut.posInSeg, rightCut.seg, rightCut.posInSeg);
		}

		const chainsToDrop = ensureCanDropChains(
			this.segs.segChains.slice(leftCut.chain + 1, rightCut.chain));

		const leftCutChain = this.getChain(leftCut.chain);
		const rightCutChain = this.getChain(rightCut.chain);
		ensureCanCutTailOf(leftCutChain, leftCut.seg, true);
		ensureCanCutHeadOf(rightCutChain);

		const leftReencrypt = await this.cutChainTail(
			leftCutChain, leftCut.seg, leftCut.posInSeg);
		const rightReencrypt = await this.cutChainHead(
			rightCutChain, rightCut.seg, rightCut.posInSeg);
		this.dropChains(chainsToDrop);

		const left = (leftReencrypt ? leftReencrypt : leftCutChain);
		const right = (rightReencrypt ? rightReencrypt : rightCutChain);
		return { left, right };
	}

	get isHeaderPacked(): boolean {
		return this.headerPacked;
	}

	get areSegmentsPacked(): boolean {
		return !this.segs.segChains.find(
			s => ((s.type === 'new') && !s.newSegs.allSegsPacked));
	}

	ensureCanPackNew(segId: SegId): void {
		const c = this.getChain(segId.chain);
		if (c.type !== 'new') { throw new Error(
			`Segment ${segId} is not in a new chain`); }
		if (!c.newSegs.isSegUnpacked(segId.seg)) { throw writeExc('segsPacked'); }
	}

	getHeaderContentToPack(): Uint8Array {
		const h = headerContentFor(this.segs);
		this.headerPacked = true;
		return h;
	}

	markAsPacked(segId: SegId): void {
		const chain = this.getChain(segId.chain);
		if (chain.type === 'new') {
			chain.newSegs.markSegPacked(segId.seg);
		}
	}

	unpackedReencryptChainSegs(): NewSegmentInfo[] {
		const reencryptSegs = this.segs.segChains
		.map((chain, chainInd) => {
			if ((chain.type !== "new")
			|| !!chain.isEndless
			|| (chain.numOfSegs > 1)
			|| !chain.headBytes
			|| (chain.headBytes.len !== chain.lastSegSize)
			|| chain.newSegs.allSegsPacked) { return; }
			const segInfo = this.index.segmentInfo(
				{ chain: chainInd, seg: 0 }, this.segInfoExtender);
			return segInfo;
		}).filter(s => !!s);
		return reencryptSegs as NewSegmentInfo[];
	}

}
Object.freeze(PackingInfo.prototype);
Object.freeze(PackingInfo);

function ensureCanDropChains(toDrop: WritableSegsChainInfo[]):
		WritableSegsChainInfo[] {
	for (const c of toDrop) {
		ensureCanDropChain(c);
	}
	return toDrop;
}

function ensureCanDropChain(c: WritableSegsChainInfo): WritableSegsChainInfo {
	if (c.type === 'new') {
		if (!c.newSegs.noSegsPacked) { throw writeExc(
			'segsPacked', `Can't drop new segment chain`); }
	}
	return c;
}

function ensureCanCutTailOf(c: WritableSegsChainInfo, lastSeg: number,
		lastSegPartial: boolean): void {
	if (c.type === 'new') {
		if (!c.newSegs.canCutTail(lastSeg, lastSegPartial)) { throw writeExc(
			'segsPacked', `Can't cut tail of a new segment chain`); }
	}
}

function ensureCanCutHeadOf(c: WritableSegsChainInfo): void {
	if (c.type === 'new') {
		if (!c.newSegs.noSegsPacked) { throw writeExc(
			'segsPacked', `Can't cut head of a new segment chain`); }
	}
}

function chainSizeForContent(contentLen: number, segSize: number):
		{ numOfSegs: number; lastSegSize: number; } {
	const numOfCompleteSegs = Math.floor(contentLen/segSize);
	const leftOvers = contentLen - numOfCompleteSegs*segSize;
	return {
		numOfSegs: numOfCompleteSegs + ((leftOvers === 0) ? 0 : 1),
		lastSegSize: (leftOvers === 0) ? segSize : leftOvers
	};
}

Object.freeze(exports);