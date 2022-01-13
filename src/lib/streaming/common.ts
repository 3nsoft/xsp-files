/*
 Copyright (C) 2016 - 2020, 2022 3NSoft Inc.
 
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

import { NONCE_LENGTH } from '../utils/crypt-utils';
import { base64urlSafe } from '../utils/buffer-utils';

/**
 * This interface is a copy of web3n.streaming.ByteSource.
 */
export interface ByteSource {
	read(len: number|undefined): Promise<Uint8Array|undefined>;
	getSize(): Promise<{ size: number; isEndless: boolean; }>;
	seek(offset: number): Promise<void>;
	getPosition(): Promise<number>;
}

/**
 * This interface is a copy of web3n.streaming.LayoutNewSection.
 */
export interface LayoutNewSection {
	src: 'new';
	ofs: number;
	len: number|undefined;
}

/**
 * This interface is a copy of web3n.streaming.LayoutBaseSection.
 */
export interface LayoutBaseSection {
	src: 'base';
	ofs: number;
	len: number;
	baseOfs: number;
}

/**
 * This interface is a copy of web3n.streaming.Layout.
 */
export interface Layout {
	base?: number,
	sections: (LayoutBaseSection|LayoutNewSection)[]
}

/**
 * This interface is a copy of web3n.streaming.ByteSink.
 */
export interface ByteSink {
	getSize(): Promise<{ size: number; isEndless: boolean; }>;
	setSize(size: number|undefined): Promise<void>;
	showLayout(): Promise<Layout>;
	spliceLayout(pos: number, del: number, ins: number): Promise<void>;
	freezeLayout(): Promise<void>;
	write(pos: number, bytes: Uint8Array): Promise<void>;
	done(err?: any): Promise<void>;
}

/**
 * This interface is a copy of web3n.Observer.
 */
export interface Observer<T> {
	next?: (value: T) => void;
	error?: (err: any) => void;
	complete?: () => void;
}

/**
 * Object has two parts: header and segments.
 * Header is usually consumed as a whole thing, while segments need a
 * byte source for access.
 * All methods should be usable when called separately from the object, i.e.
 * all methods must be functions, already bound to some state/closure.
 */
export interface ObjSource {
	
	version: number;
	
	/**
	 * This returns a promise, resolvable to a complete header byte array.
	 */
	readHeader(): Promise<Uint8Array>;
	
	segSrc: ByteSource;
}

export function idToHeaderNonce(objId: string): Uint8Array {
	if ((3 * objId.length/4) !== NONCE_LENGTH) { throw new Error(
		`Given object id ${objId} doesn't have expected length`); }
	const nonce = base64urlSafe.open(objId);
	if (nonce.length !== NONCE_LENGTH) { throw new Error(
		`Nonce cannot be extracted from a given object id ${objId}`); }
	return nonce;
}

Object.freeze(exports);