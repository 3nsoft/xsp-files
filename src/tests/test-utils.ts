/* Copyright(c) 2013 - 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { arrays, secret_box as sbox } from 'ecma-nacl';
import { AsyncSBoxCryptor } from '../lib/crypt-utils';

export { randomBytes as getRandom } from 'crypto';

export function compare(v: Uint8Array, expectation: Array<number>, m? :string);
export function compare(v: Uint8Array, expectation: Uint8Array, m? :string);
export function compare(v: Uint8Array, expectation, m? :string) {
	expect(v.length).toBe(expectation.length,
		`arrays have different sizes; ${m}`);
	for (let i=0; i<v.length; i+=1) {
		expect(v[i]).toBe(expectation[i],
			`${i}-th array element are different; ${m}`)
	}
}

export function mockCryptor(): AsyncSBoxCryptor {
	const arrFactory = arrays.makeFactory();
	const ac: AsyncSBoxCryptor = {
		open: async (c, n, k) => sbox.open(c, n, k, arrFactory),
		pack: async (m, n, k) => sbox.pack(m, n, k, arrFactory),
		formatWN: {
			open: async (c, k) => sbox.formatWN.open(c, k, arrFactory),
			pack: async (m, n, k) => sbox.formatWN.pack(m, n, k, arrFactory),
		}
	};
	return Object.freeze(ac);
}

export function totalLengthOfByteArrays(arrays: Uint8Array[]): number {
	return arrays.reduce((totalLen, arr) => (totalLen + arr.length), 0);
}

export function combineByteArrays(arrays: Uint8Array[]): Uint8Array {
	const combinedArray = new Uint8Array(totalLengthOfByteArrays(arrays));
	let offset = 0;
	for (let i=0; i<arrays.length; i+=1) {
		combinedArray.set(arrays[i], offset);
		offset += arrays[i].length;
	}
	return combinedArray;
}

Object.freeze(exports);