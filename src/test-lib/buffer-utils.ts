/*
 Copyright (C) 2016, 2018 - 2020 3NSoft Inc.
 
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

export const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Buffer and Uint8Array are intimately linked in Node, starting with some
 * version. As a result, Uint8Array can be efficiently turned into Buffer,
 * or Buffer can be used as Uint8Array.
 * This function checks if given argument is a Buffer, and, if not, does
 * proper enveloping.
 * @param bytes that we need to have as a Buffer
 * @return Buffer with given bytes. 
 */
export function toBuffer(bytes: Uint8Array): Buffer {
	if (Buffer.isBuffer(bytes)) { return bytes; }
	if (bytes.length === 0) { return EMPTY_BUFFER; }
	return Buffer.from(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.length);
}

/**
 * Node's JSON.stringify turns Buffer into a particular json.
 * This function turns this json back to Buffer.
 * @param json of a Buffer
 * @return a Buffer reconstructed from a given json.
 */
export function bufFromJson(json: any): Buffer {
	if ((json.type !== 'Buffer') || !Array.isArray(json.data)) { throw new Error(
		'Given argument is not a buffer json.'); }
	return Buffer.from(json.data);
}

export namespace base64 {
	
	export function pack(bytes: Uint8Array): string {
		const buf = toBuffer(bytes);
		return buf.toString('base64');
	}
	
	export function open(str: string): Uint8Array {
		return Buffer.from(str, 'base64');
	}
	
}
Object.freeze(base64);

export namespace base64urlSafe {
	
	export function pack(bytes: Uint8Array): string {
		const str = base64.pack(bytes);
		return str
			.replace(/\+/g, '-')
			.replace(/\//g, '_');
	}
	
	export function open(str: string): Uint8Array {
		str = str
			.replace(/-/g, '+')
			.replace(/_/g, '/');
		return base64.open(str);
	}
	
}
Object.freeze(base64);

export namespace utf8 {
	
	export function pack(str: string): Uint8Array {
		return Buffer.from(str, 'utf8');
	}
	
	export function open(bytes: Uint8Array): string {
		const buf = toBuffer(bytes);
		return buf.toString('utf8');
	}
	
}
Object.freeze(utf8);

export function joinByteArrs(arrs: Uint8Array[]): Uint8Array {
	let totalLen = 0;
	for (const arr of arrs) {
		totalLen += arr.length;
	}
	const allBytes = Buffer.allocUnsafe(totalLen);
	let ofs = 0;
	for (const arr of arrs) {
		allBytes.set(arr, ofs);
		ofs += arr.length;
	}
	return allBytes;
}

export function byteLengthIn(arrs: Uint8Array[]): number {
	let len = 0;
	for (let i=0; i<arrs.length; i+=1) {
		len += arrs[i].length;
	}
	return len;
}

Object.freeze(exports);