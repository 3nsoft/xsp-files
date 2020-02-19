/*
 Copyright(c) 2018 - 2020 3NSoft Inc.
 
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

import { ByteSource, ByteSink, Layout } from '../lib/streaming/common';

class WriterToArray implements ByteSink {

	private deferred: {
		resolve: (completeArray: Uint8Array) => void;
		reject: (err: any) => void;
	}|undefined;
	private completion: Promise<Uint8Array>;

	private chunks: {
		ofs: number;
		bytes: Uint8Array;
	}[] = [];
	private size: number|undefined = undefined;
	private isLayoutFrozen = false;

	constructor() {
		this.completion = new Promise((resolve, reject) => {
			this.deferred = { resolve, reject };
		});
		Object.seal(this);
	}

	private ensureNotDone(): void {
		if (!this.deferred) { throw new Error(`Writer is already done`); }
	}

	private ensureLayoutNotFrozen(): void {
		if (this.isLayoutFrozen) { throw new Error(
			`Can't change size, cause layout is already frozen`); }
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		this.ensureNotDone();
		return ((typeof this.size === 'number') ?
			{ size: this.size, isEndless: false } :
			{ size: 0, isEndless: true });
	}

	async setSize(size: number|undefined): Promise<void> {
		this.ensureNotDone();
		this.ensureLayoutNotFrozen();

		if ((size === undefined)
		|| ((this.size !== undefined) && (size >= this.size))
		|| (this.chunks.length === 0)) {
			this.size = size;
			return;
		}

		const last = this.chunks[this.chunks.length-1];
		if ((last.ofs + last.bytes.length) > size) { throw new Error(
			`Can't cut already written bytes`); }
		this.size = size;
	}

	async showLayout(): Promise<Layout> {
		return {
			sections :[ {
				src: 'new',
				ofs: 0,
				len: this.size
			} ]
		};
	}

	async spliceLayout(pos: number, del: number, ins: number): Promise<void> {
		this.ensureNotDone();
		this.ensureLayoutNotFrozen();
		if ((del === 0) && (ins === 0)) { return; }
		if (this.chunks.length > 0) {
			const last = this.chunks[this.chunks.length-1];
			if ((last.ofs + last.bytes.length) > pos) { throw new Error(
				`Can't cut already written bytes`); }
		}
		if (this.size === undefined) { return; }
		this.size += ins - del;
	}

	async freezeLayout(): Promise<void> {
		this.ensureNotDone();
		this.isLayoutFrozen = true;
	}

	async write(pos: number, bytes: Uint8Array): Promise<void> {
		if ((this.size !== undefined)
		&& ((pos + bytes.length) > this.size)) { throw new Error(
			`Can't write outside of the layout`); }

		const bytesEnd = pos + bytes.length;
		let index = 0;
		for (; index<this.chunks.length; index+=1) {
			const chunk = this.chunks[index];
			if (bytesEnd <= chunk.ofs) { break; }
			if (pos < (chunk.ofs + chunk.bytes.length)) { throw new Error(
				`Can't write over already written data`); }
		}

		this.chunks.splice(index, 0, {
			ofs: pos,
			bytes: new Uint8Array(bytes)
		});
	}

	async done(err?: any): Promise<void> {
		if (!this.deferred) { return; }
		if (err) {
			this.deferred.reject(err);
			this.deferred = undefined;
			return;
		}

		// check if all bytes are present
		let expectedOfs = 0;
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			if (expectedOfs !== chunk.ofs) { throw new Error(
				`Completion is impossible as not all bytes are written`); }
			expectedOfs += chunk.bytes.length;
		}
		if ((this.size !== undefined) && (expectedOfs !== this.size)) {
			throw new Error(
				`Completion is impossible as not all bytes are written`);
		}

		// pack and resolve
		const all = new Uint8Array(expectedOfs);
		for (let i=0; i<this.chunks.length; i+=1) {
			const chunk = this.chunks[i];
			all.set(chunk.bytes, chunk.ofs);
		}
		this.deferred.resolve(all);
		this.deferred = undefined;
	}
	
	get completeArray(): Promise<Uint8Array> {
		return this.completion;
	}

	wrap(): ByteSink {
		const w: ByteSink = {
			getSize: this.getSize.bind(this),
			setSize: this.setSize.bind(this),
			showLayout: this.showLayout.bind(this),
			spliceLayout: this.spliceLayout.bind(this),
			freezeLayout: this.freezeLayout.bind(this),
			write: this.write.bind(this),
			done: this.done.bind(this)
		};
		return w;
	}

}
Object.freeze(WriterToArray.prototype);
Object.freeze(WriterToArray);

export function writerToArray():
		{ writer: ByteSink; completeArray: Promise<Uint8Array>; } {
	const writer = new WriterToArray();
	return {
		writer: writer.wrap(),
		completeArray: writer.completeArray
	}
}

class SourceFromArray implements ByteSource {

	private position = 0;

	constructor(
		private array: Uint8Array
	) {
		Object.seal(this);
	}

	async read(len: number|undefined): Promise<Uint8Array|undefined> {
		if (len === undefined) {
			const bytes = this.array.subarray(this.position);
			this.position += bytes.length;
			return ((bytes.length === 0) ? undefined : bytes);
		}

		if (!Number.isInteger(len) || (len < 0)) { throw new Error(
			`Given bad length parameter: ${len}`); }

		const bytes = this.array.subarray(this.position, this.position+len);
		this.position += bytes.length;
		return ((bytes.length === 0) ? undefined : bytes);
	}

	async getSize(): Promise<{ size: number; isEndless: boolean; }> {
		return { size: this.array.length, isEndless: false };
	}

	async seek(offset: number): Promise<void> {
		if (!Number.isInteger(offset)
		|| (offset < 0) || (this.array.length < offset)) { throw new Error(
			`Given bad or out of bounds offset: ${offset}`); }
		this.position = offset;
	}

	async getPosition(): Promise<number> {
		return this.position;
	}

	wrap(): ByteSource {
		const w: ByteSource = {
			read: this.read.bind(this),
			getSize: this.getSize.bind(this),
			getPosition: this.getPosition.bind(this),
			seek: this.seek.bind(this)
		};
		return w;
	}

}
Object.freeze(SourceFromArray.prototype);
Object.freeze(SourceFromArray);

export function sourceFromArray(bytes: Uint8Array): ByteSource {
	const s = new SourceFromArray(bytes);
	return s.wrap();
}

Object.freeze(exports);