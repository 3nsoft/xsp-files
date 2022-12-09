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

// XXX
//  - Can we make a cryptor with workers?
//    It will allow playing with code to find convenient interface, and to
//    actually test here that streaming uses parallel processes.
//  - Every other project simply needs to know what interface is expected by
//    xsp streaming. Where and how encryption tasks are executed is not of any
//    concern for streaming lib. But, it should reason about having several
//    processes and several obj tasks.
//    We want to parallelize single obj tasks, while distributing resources when
//    there are many simultaneous obj read/written.
//  - BatchCryptor ?
//    To encapsulate own work batches?
//    And these batches are alway connected to either SegmentsWriter or
//    SegmentsReader. May be have batch-knowing wrap with state here, powered
//    by some corrected shared AsyncSBoxCryptor resource.

export function mockCryptor(): AsyncSBoxCryptor {
	const arrFactory = arrays.makeFactory();
	const numOfWorkers = 3;
	const workQueues = new Map<number, number>();
	function addToWorkQueue(workLabel: number): void {
		const inQueue = workQueues.get(workLabel);
		workQueues.set(workLabel, (inQueue ? inQueue+1 : 1));
	}
	function removeFromWorkQueue(workLabel: number): void {
		const inQueue = workQueues.get(workLabel);
		if (inQueue && (inQueue > 1)) {
			workQueues.set(workLabel, inQueue-1);
		} else {
			workQueues.delete(workLabel);
		}
	}
	function canStartUnderWorkLabel(workLabel: number): number {
		const maxIdle = numOfWorkers - workQueues.size;
		if (maxIdle <= 0) {
			return (workQueues.has(workLabel) ? 0 : 1);
		}
		const inQueue = workQueues.get(workLabel);
		return (inQueue ? Math.max(0, ) : maxIdle);
	}
	async function exec<T>(workLabel: number, op: () => T): Promise<T> {
		addToWorkQueue(workLabel);
		try {
			return await onNextTick(op);
		} finally {
			removeFromWorkQueue(workLabel);
		}
	}
	const ac: AsyncSBoxCryptor = {
		canStartUnderWorkLabel,
		open: (c, n, k, workLabel) => exec(
			workLabel,
			() => sbox.open(c, n, k, arrFactory)
		),
		pack: (m, n, k, workLabel) => exec(
			workLabel,
			() => sbox.pack(m, n, k, arrFactory)
		),
		formatWN: {
			open: (c, k, workLabel) => exec(
				workLabel,
				() => sbox.formatWN.open(c, k, arrFactory)
			),
			pack: (m, n, k, workLabel) => exec(
				workLabel,
				() => sbox.formatWN.pack(m, n, k, arrFactory)
			)
		}
	};
	return Object.freeze(ac);
}

async function onNextTick<T>(action: () => T): Promise<T> {
	return new Promise<T>((resolve, reject) => process.nextTick(() => {
		try {
			resolve(action());
		} catch (err) {
			reject(err);
		}
	}));
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