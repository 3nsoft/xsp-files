/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import { arrays, secret_box as sbox } from 'ecma-nacl';
import { SegmentsWriter, SegWriter } from './segments/writer';
import { SegmentsReader, SegReader } from './segments/reader';
import { bind } from './binding';

export interface FileKeyHolder {

	getKey(): Uint8Array;

	/**
	 * @param encr is a file key encryptor, for reencryption
	 * @param header is original file header
	 * @return a new file header
	 */
	reencryptKey(encr: sbox.Encryptor, header: Uint8Array): Uint8Array;
	
	/**
	 * @param segSizein256bs is a default segment size in 256-byte blocks
	 * @param randomBytes is a function that produces cryptographically strong
	 * random numbers (bytes).
	 * @return segments writer either for a new file, or for a complete
	 * replacement of existing file's bytes.
	 */
	newSegWriter(segSizein256bs: number,
		randomBytes: (n: number) => Uint8Array): SegmentsWriter;
	
	/**
	 * @param header is an array with file's header. Array must contain only
	 * header's bytes, as its length is used to decide how to process it.
	 * @param randomBytes is a function that produces cryptographically strong
	 * random numbers (bytes).
	 * @return segments writer for changing existing file.
	 */
	segWriter(header: Uint8Array, randomBytes: (n: number) => Uint8Array):
		SegmentsWriter;
	
	/**
	 * @param header is an array with file's header. Array must contain only
	 * header's bytes, as its length is used to decide how to process it.
	 * @return segment reader
	 */
	segReader(header: Uint8Array): SegmentsReader;
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
	/**
	 * @param (optional) array factory for use by cloned key holder.
	 * @return creates a clone of this key holder, cloning key and all internals.
	 */
	clone(arrFactory?: arrays.Factory): FileKeyHolder;
	
}

export const KEY_PACK_LENGTH: number = 72;

class KeyHolder implements FileKeyHolder {
	
	private arrFactory: arrays.Factory;
	
	constructor(
			private key: Uint8Array,
			private keyPack: Uint8Array|undefined,
			arrFactory?: arrays.Factory) {
		this.arrFactory =  (arrFactory ?
			arrFactory : arrays.makeFactory());
		Object.seal(this);
	}

	getKey(): Uint8Array {
		return this.key;
	}

	isReadOnly(): boolean {
		return (this.keyPack === undefined);
	}
	
	reencryptKey(encr: sbox.Encryptor, header: Uint8Array): Uint8Array {
		this.keyPack = encr.pack(this.key);
		let newHeader = new Uint8Array(header.length);
		newHeader.set(this.keyPack);
		newHeader.set(header.subarray(this.keyPack.length), this.keyPack.length);
		return newHeader;
	}

	newSegWriter(segSizein256bs: number,
			randomBytes: (n: number) => Uint8Array): SegmentsWriter {
		if (this.isReadOnly()) { throw new Error(`Read-only key holder cannot make segments writer.`); }
		var writer = new SegWriter(this.key, this.keyPack!,
			undefined, segSizein256bs, randomBytes, this.arrFactory);
		return writer.wrap();
	}
	
	segWriter(header: Uint8Array,
			randomBytes: (n: number) => Uint8Array): SegmentsWriter {
		var writer = new SegWriter(this.key,
				new Uint8Array(header.subarray(0,KEY_PACK_LENGTH)),
				header.subarray(KEY_PACK_LENGTH), undefined,
				randomBytes, this.arrFactory);
		return writer.wrap();
	}
	
	segReader(header: Uint8Array): SegmentsReader {
		var reader = new SegReader(this.key,
			header.subarray(KEY_PACK_LENGTH), this.arrFactory);
		return reader.wrap();
	}
	
	destroy(): void {
		if (this.key) {
			arrays.wipe(this.key);
			this.key = (undefined as any);
		}
		this.keyPack = (undefined as any);
		if (this.arrFactory) {
			this.arrFactory.wipeRecycled();
			this.arrFactory = (undefined as any);
		}
	}
	
	clone(arrFactory?: arrays.Factory): FileKeyHolder {
		var key = new Uint8Array(this.key.length);
		key.set(this.key);
		if (!arrFactory) {
			arrFactory = this.arrFactory;
		}
		var kh = new KeyHolder(key, this.keyPack, arrFactory);
		return kh.wrap();
	}
	
	wrap(): FileKeyHolder {
		var wrap: FileKeyHolder = {
			destroy: bind(this, this.destroy),
			reencryptKey: bind(this, this.reencryptKey),
			newSegWriter: bind(this, this.newSegWriter),
			segWriter: bind(this, this.segWriter),
			segReader: bind(this, this.segReader),
			clone: bind(this, this.clone),
			getKey: bind(this, this.getKey)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}

/**
 * @param mkeyEncr master key encryptor, which is used to make file key pack.
 * @param randomBytes is a function that produces cryptographically strong
 * random numbers (bytes).
 * @param arrFactory (optional) array factory
 * @return file key holder with a newly generated key.
 */
export function makeNewFileKeyHolder(mkeyEncr: sbox.Encryptor,
		randomBytes: (n: number) => Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKey = randomBytes(sbox.KEY_LENGTH);
	var fileKeyPack = mkeyEncr.pack(fileKey);
	var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
	return kh.wrap();
}

/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
export function makeFileKeyHolder(mkeyDecr: sbox.Decryptor, header: Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
	var fileKey = mkeyDecr.open(fileKeyPack);
	var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
	return kh.wrap();
}

/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
export function makeReadOnlyFileKeyHolder(mkeyDecr: sbox.Decryptor,
		header: Uint8Array, arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
	var fileKey = mkeyDecr.open(fileKeyPack);
	var kh = new KeyHolder(fileKey, undefined, arrFactory);
	return kh.wrap();
}

/**
 * @param fkey is a file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a given key.
 */
export function makeHolderFor(fkey: Uint8Array, header: Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
	var kh = new KeyHolder(fkey, fileKeyPack, arrFactory);
	return kh.wrap();
}

/**
 * @param fkey is a file key.
 * @param arrFactory (optional) array factory
 * @return file key holder with a given key.
 */
export function makeReadOnlyHolderFor(fkey: Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var kh = new KeyHolder(fkey, undefined, arrFactory);
	return kh.wrap();
}

Object.freeze(exports);