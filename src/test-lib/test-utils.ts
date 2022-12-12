/*
 Copyright(c) 2013 - 2018, 2022 3NSoft Inc.
 
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

import { arrays, secret_box as sbox } from 'ecma-nacl';
import { AsyncSBoxCryptor } from '../lib/utils/crypt-utils';
import { randomBytes } from 'crypto';
import { ObjSource } from '../lib';
import { sourceFromArray } from './array-backed-byte-streaming';
import { InProcAsyncExecutor } from './work-labels';

export { randomBytes as getRandomSync } from 'crypto';

export function getRandom(numOfBytes: number): Promise<Uint8Array> {
	return new Promise((res, rej) => randomBytes(numOfBytes, (err, buf) => {
		if (err) { rej(err); }
		else { res(buf); }
	}))
}

export function compare(
	v: Uint8Array, expectation: Array<number>, m? :string): void;
export function compare(
	v: Uint8Array, expectation: Uint8Array, m? :string): void;
export function compare(
	v: Uint8Array, expectation: Array<number>|Uint8Array, m? :string
): void {
	if (v.length !== expectation.length) { throw new Error(
		`arrays have different sizes; ${m}`); }
	for (let i=0; i<v.length; i+=1) {
		if (v[i] !== expectation[i]) { throw new Error(
			`${i}-th array element are different; ${m}`); }
	}
}

export function mockCryptor(): AsyncSBoxCryptor {
	const arrFactory = arrays.makeFactory();
	const workExecutor = new InProcAsyncExecutor();
	const ac: AsyncSBoxCryptor = {
		canStartUnderWorkLabel: l => workExecutor.canStartUnderWorkLabel(l),
		open: (c, n, k, workLabel) => workExecutor.execOpOnNextTick(
			workLabel,
			() => sbox.open(c, n, k, arrFactory)
		),
		pack: (m, n, k, workLabel) => workExecutor.execOpOnNextTick(
			workLabel,
			() => sbox.pack(m, n, k, arrFactory)
		),
		formatWN: {
			open: (c, k, workLabel) => workExecutor.execOpOnNextTick(
				workLabel,
				() => sbox.formatWN.open(c, k, arrFactory)
			),
			pack: (m, n, k, workLabel) => workExecutor.execOpOnNextTick(
				workLabel,
				() => sbox.formatWN.pack(m, n, k, arrFactory)
			)
		}
	};
	return Object.freeze(ac);
}

export function objSrcFromArrays(
	version: number, header: Uint8Array, segs: Uint8Array
): ObjSource {
	const segSrc = sourceFromArray(segs);
	return {
		version,
		readHeader: async () => header,
		segSrc
	};
}

export function toOneArray(arrs: Uint8Array[]): Uint8Array {
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

function totalLengthOf(arrs: Uint8Array[]): number {
	let len = 0;
	for (let i=0; i<arrs.length; i+=1) {
		len += arrs[i].length;
	}
	return len;
}


Object.freeze(exports);