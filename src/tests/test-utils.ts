/* Copyright(c) 2013 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

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

export function asciiStrToUint8Array(str: string): Uint8Array {
	var arr = new Uint8Array(str.length);
	for (var i=0; i<str.length; i+=1) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}
