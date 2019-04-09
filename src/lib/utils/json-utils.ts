/*
 Copyright (C) 2016 - 2018 3NSoft Inc.
 
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


/**
 * This function creates a copy of json entity with a caveat that Buffer and
 * byte arrays are shared between original and a copy.
 * @param orig is an object, which copy is created. Buffer and byte arrays
 * passed through like primitives.
 * @param excludeTopFields is an optional list of fields to exclude from copy.
 */
export function copy<T>(orig: T, excludeTopFields?: string[]): T {
	const origType = typeof orig;
	if (origType !== 'object') {
		return ((origType !== 'function') ? orig : (undefined as any));
	}
	if (orig === null) { return (null as any); }
	if (Buffer.isBuffer(orig)) { return (orig as any); }
	if (ArrayBuffer.isView(orig)) { return (orig as any); }
	if (Array.isArray(orig)) {
		const arr: any[] = orig;
		const c: any[] = [];
		for (let i=0; i < arr.length; i+=1) {
			c[i] = copy(arr[i]);
		}
		return (c as any);
	} else {
		const c = ({} as T);
		const fields = Object.keys(orig);
		if (excludeTopFields) {
			for (const f of fields) {
				if (excludeTopFields.includes(f)) { continue; }
				c[f] = copy<any>(orig[f]);
			}
		} else {
			for (const f of fields) {
				c[f] = copy<any>(orig[f]);
			}
		}
		return c;
	}
}

export function deepEqual(a: any, b: any): boolean {
	
	const t = typeof a;
	
	if (t !== typeof b) { return false; }
	
	if (t !== 'object') {
		return (a === b);
	}
	
	if (a === b) { return true; }
	if ((a === null) || (b === null)) { return false; }
		
	if (Array.isArray(a)) {
		if (!Array.isArray(b)) { return false; }
		const aArr = <Array<any>> a;
		const bArr = <Array<any>> b;
		if (aArr.length !== bArr.length) { return false; }
		for (let i=0; i<aArr.length; i+=1) {
			if (!deepEqual(aArr[i], bArr[i])) { return false; }
		}
	} else {
		const keys = Object.keys(a);
		if (keys.length !== Object.keys(b).length) { return false; }
		for (let i=0; i<keys.length; i+=1) {
			const key = keys[i];
			if (!deepEqual(a[key], b[key])) { return false; }
		}
	}
	
	return true;
}

export function* deepFind(a: any, predicate: (val: any) => boolean):
		IterableIterator<{ pos: string[]; val: any; }> {
	if ((typeof a !== 'object') || !a) {
		if (predicate(a)) {
			yield { pos: [], val: a };
		}
		return;
	}

	for (const field in a) {
		const val = a[field];
		if (predicate(val)) {
			yield { pos: [ field ], val };
		} else {
			for (const inner of deepFind(val, predicate)) {
				inner.pos.unshift(field);
				yield inner;
			}
		}
	}
}

/**
 * This function applies given changes to object.
 * @param json is an object that is being changed
 * @param changes is a set of changes to apply to an object. Undefined value in
 * in a fields means that respective field should be deleted from an object.
 */
export function applyChangesToJSON<T>(json: T, changes: Partial<T>): void {
	for (const f of Object.keys(changes)) {
		const newValue = changes[f as keyof T];
		if (newValue === undefined) {
			delete json[f];
		} else {
			json[f] = newValue;
		}
	}
}

Object.freeze(exports);