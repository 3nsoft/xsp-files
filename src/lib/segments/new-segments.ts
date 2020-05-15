/*
 Copyright(c) 2018 3NSoft Inc.
 
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

import { MAX_SEG_INDEX } from './xsp-info';
import { assert } from '../utils/assert';
import { writeExc } from './writer';

type ChainInfo =  { isEndless: true; }|{ numOfSegs: number; isEndless?: undefined; };

/**
 * This structure is used in packing info for tracking state of new segment
 * chains.
 */
export class NewSegments {

	/**
	 * This array represents an ordered sequence of segments [start,end], with
	 * both numbers being inclusive. E.g. [5,5] represents a sequence that
	 * contains number 5, while [5,6] contains numbers 5 and 6.
	 * Indecies of packed segments are not in this sequence!
	 */
	private unpackedSegs: [number, number][];

	/**
	 * This is a memory of the highest segment in the chain. We need this to
	 * calculate packed segments from known unpacked ones.
	 */
	private maxSegIndex: number;

	constructor(chainInfo: ChainInfo) {
		this.maxSegIndex = (chainInfo.isEndless ? MAX_SEG_INDEX : chainInfo.numOfSegs-1);
		if (!(this.maxSegIndex >= 0)) { throw new Error(
			`Have an illegal chain with zero segments.`); }
		this.unpackedSegs = [ [0, this.maxSegIndex] ];
		Object.seal(this);
	}

	get indexOfRightmostPackedSeg(): number|undefined {
		if (this.unpackedSegs.length === 0) { return this.maxSegIndex; }
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		if (last[1] === this.maxSegIndex) {
			return ((last[0] === 0) ? undefined : (last[0] - 1));
		} else {
			return this.maxSegIndex;
		}
	}

	canGrowTail(): boolean {
		if (this.unpackedSegs.length === 0) { return false; }
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		return (last[1] === this.maxSegIndex);
	}

	growTail(newLastSeg: number): void {
		assert(newLastSeg >= this.maxSegIndex,
			`Invalid slice index ${newLastSeg} for growing chain with max slice ${this.maxSegIndex}`);
		assert(newLastSeg < MAX_SEG_INDEX,
			`Invalid slice index ${newLastSeg} for growing chain with max slice ${this.maxSegIndex}`);
		if (!this.canGrowTail()) { throw writeExc(
				'segsPacked', `Can't grow new chain`); }
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		last[1] = newLastSeg;
		this.maxSegIndex = newLastSeg;
	}

	turnIntoEndlessChain(): boolean {
		if (!this.canGrowTail()) { return false; }
		this.maxSegIndex = MAX_SEG_INDEX;
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		last[1] = this.maxSegIndex;
		return true;
	}

	canCutTail(newLastSeg: number, lastSegPartial: boolean): boolean {
		if (this.unpackedSegs.length === 0) { return false; }
		assert(newLastSeg <= this.maxSegIndex,
			`Invalid slice index ${newLastSeg} for cutting chain with max slice ${this.maxSegIndex}`);
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		return (lastSegPartial ?
			(last[0] <= newLastSeg) : ((last[0] - 1) <= newLastSeg));
	}

	cutTail(lastSeg: number, lastSegPartial: boolean): void {
		if (!this.canCutTail(lastSeg, lastSegPartial)) { throw writeExc(
			'segsPacked', `Can't cut tail of a new segment chain`); }
		const last = this.unpackedSegs[this.unpackedSegs.length-1];
		if (lastSegPartial) {
			assert(last[0] <= lastSeg);
			last[1] = lastSeg;
		} else {
			assert(last[0] <= (lastSeg + 1));
			if (last[0] === lastSeg+1) {
				this.unpackedSegs.pop();
			} else {
				last[1] = lastSeg;
			}
		}
		this.maxSegIndex = lastSeg;
	}

	isSegUnpacked(seg: number): boolean {
		return !!this.unpackedSegs.find(s => ((s[0] <= seg) && (seg <= s[1])));
	}

	markSegPacked(seg: number): void {
		const ind = this.unpackedSegs.findIndex(
			s => ((s[0] <= seg) && (seg <= s[1])));
		if (ind < 0) { return; }
		const s = this.unpackedSegs[ind];
		if (seg === s[0]) {
			s[0] += 1;
			if (s[0] > s[1]) {
				this.unpackedSegs.splice(ind, 1);
			}
		} else if (seg === s[1]) {
			s[1] -= 1;
			if (s[0] > s[1]) {
				this.unpackedSegs.splice(ind, 1);
			}
		} else {
			const left: [number, number] = [s[0], seg-1];
			const right: [number, number] = [seg+1, s[1]];
			this.unpackedSegs.splice(ind, 1, left, right);
		}
	}
	
	get noSegsPacked(): boolean {
		if (this.unpackedSegs.length !== 1) { return false; }
		return ((this.unpackedSegs[0][0] === 0) &&
			(this.unpackedSegs[0][1] === this.maxSegIndex));
	}

	get allSegsPacked(): boolean {
		if (this.unpackedSegs.length === 0) { return true; }
		if ((this.maxSegIndex === MAX_SEG_INDEX)
		&& (this.unpackedSegs.length === 1)) {
			const last = this.unpackedSegs[this.unpackedSegs.length-1];
			if (last[1] === MAX_SEG_INDEX) { return true; }
		}
		return false;
	}

}
Object.freeze(NewSegments.prototype);
Object.freeze(NewSegments);

Object.freeze(exports);