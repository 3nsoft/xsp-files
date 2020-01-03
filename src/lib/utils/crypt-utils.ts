/*
 Copyright(c) 2017 3NSoft Inc.
 
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

export interface AsyncSBoxCryptor {

	/**
	 * This returns a promise, resolvable to Uint8Array with opened message.
	 * @param c is Uint8Array of cipher bytes that need to be opened.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 */
	open(c: Uint8Array, n: Uint8Array, k: Uint8Array): Promise<Uint8Array>;

	/**
	 * This returns a promise, resolvable to Uint8Array with resulting cipher of
	 * incoming message, packaged according to NaCl's xsalsa20+poly1305
	 * secret-box bytes layout.
	 * @param m is Uint8Array of message bytes that need to be encrypted.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 */
	pack(m: Uint8Array, n: Uint8Array, k: Uint8Array): Promise<Uint8Array>;

	formatWN: {

		/**
		 * This returns a promise, resolvable to Uint8Array, where nonce is packed
		 * together with NaCl's cipher.
		 * Length of the returned array is 40 bytes greater than that of a
		 * message.
		 * @param m is Uint8Array of message bytes that need to be encrypted.
		 * @param n is Uint8Array, 24 bytes long nonce.
		 * @param k is Uint8Array, 32 bytes long secret key.
		 */
		pack(m: Uint8Array, n: Uint8Array, k: Uint8Array): Promise<Uint8Array>;

		/**
		 * This returns a promise, resolvable to Uint8Array with opened message.
		 * @param cn is Uint8Array with nonce and cipher bytes that need to be
		 * opened.
		 * @param k is Uint8Array, 32 bytes long secret key.
		 */
		open(cn: Uint8Array, k: Uint8Array): Promise<Uint8Array>;
	};

}

/**
 * Return new nonce, calculated from an initial one by adding a delta to it.
 * @param initNonce
 * @param delta
 */
export function calculateNonce(
	initNonce: Uint8Array, delta: number|U64
): Uint8Array {
	let deltaU64: U64;
	let adding: boolean;
	if (typeof delta === 'number') {
		if ((delta > 0xfffffffffffff) || (delta < -0xfffffffffffff)) {
			throw new Error("Given delta is out of limits."); }
		if (delta > 0) {
			adding = true;
		} else if (delta < 0) {
			delta = -delta;
			adding = false;
		} else {
			return new Uint8Array(initNonce);
		}
		deltaU64 = new Uint32Array([ delta, delta/0x100000000 ]);
	} else {
		deltaU64 = delta;
		adding = true;
	}
	const n = new Uint8Array(24);
	for (let i=0; i < 3; i+=1) {
		const chunk = (adding ?
			addU64(loadLEU64(initNonce, i*8), deltaU64) :
			subU64(loadLEU64(initNonce, i*8), deltaU64));
		storeLEU64(n, i*8, chunk);
	}
	return n;
}

/**
 * This array contains 64 bits in two unsigned ints, with high 32 bits in the
 * 1st element and low 32 bits in the 0th one.
 */
export interface U64 extends Uint32Array {}

/**
 * @param u is a U64 object
 */
export function nonceDeltaToNumber(u: U64): number|undefined {
	if (u[1] > 0xfffff) { return; }
	return u[1] * 0x100000000 + u[0];
}

function addU64(a: U64, b: U64): U64 {
	const l = a[0] + b[0];
	const h = a[1] + b[1] + ((l / 0x100000000) | 0);
	return new Uint32Array([ l, h ]);
}

function subU64(a: U64, b: U64): U64 {
	let h = a[1] - b[1];
	let l = a[0] - b[0];
	if (l < 0) {
		h -= 1;
		l += 0x100000000;
	}
	return new Uint32Array([ l, h ]);
}

function loadLEU64(x: Uint8Array, i: number): U64 {
	const l = (x[i+3] << 24) | (x[i+2] << 16) | (x[i+1] << 8) | x[i];
	const h = (x[i+7] << 24) | (x[i+6] << 16) | (x[i+5] << 8) | x[i+4];
	return new Uint32Array([ l, h ]);
}

function storeLEU64(x: Uint8Array, i: number, u: U64): void {
	x[i+7] = u[1] >>> 24;
	x[i+6] = u[1] >>> 16;
	x[i+5] = u[1] >>> 8;
	x[i+4] = u[1];
	x[i+3] = u[0] >>> 24;
	x[i+2] = u[0] >>> 16;
	x[i+1] = u[0] >>> 8;
	x[i] = u[0];
}

/**
 * This returns delta (unsigned 64-bit integer), which, when added to the first
 * nonce (n1), produces the second nonce (n2).
 * Undefined is returned, if given nonces are not related to each other.
 * @param n1
 * @param n2
 */
export function findNonceDelta(n1: Uint8Array, n2: Uint8Array): U64|undefined {
	var delta = subU64(loadLEU64(n2, 0), loadLEU64(n1, 0));
	var dx: U64;
	for (var i=1; i < 3; i+=1) {
		dx = subU64(loadLEU64(n2, i*8), loadLEU64(n1, i*8));
		if ((delta[0] !== dx[0]) || (delta[1] !== dx[1])) { return; }
	}
	return delta;
}

/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * a given delta to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 * @param delta is a number from 1 to 255 inclusive.
 */
export function advanceNonce(n: Uint8Array, delta: number): void {
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	if ((delta < 1) || (delta > 255)) { throw new Error(
			"Given delta is out of limits."); }
	var deltaU64 =  new Uint32Array([ delta, 0 ]);
	for (var i=0; i < 3; i+=1) {
		storeLEU64(n, i*8, addU64(loadLEU64(n, i*8), deltaU64));
	}
}

/**
 * NaCl's secret key length.
 */
export const KEY_LENGTH = 32;

/**
 * NaCl's secret key authenticated encryption nonce's length.
 */
export const NONCE_LENGTH = 24;

/**
 * NaCl's poly hash length.
 */
export const POLY_LENGTH = 16;

/**
 * Returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 * Comparison check lengths first, failing fast if lengths are different.
 * Comparison of elements is done in constant time.
 * @param x
 * @param y
 */
export function compareVectors(x: Uint8Array, y: Uint8Array): boolean {
	if (x.length !== y.length) { return false; }
	let differentbits = 0;
	for (let i=0; i<x.length; i+=1) {
		differentbits |= x[i] ^ y[i];
	}
	return (differentbits === 0);
}

Object.freeze(exports);