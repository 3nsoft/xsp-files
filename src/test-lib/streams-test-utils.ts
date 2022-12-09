/*
 Copyright (C) 2018 - 2020, 2022 3NSoft Inc.
 
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

import { makeSegmentsWriter, ByteSink, Layout, ObjSource, makeEncryptingByteSink, EncrEvent, SegEncrEvent, AsyncSBoxCryptor, makeSegmentsReader, ByteSource } from '../lib';
import { getRandom, objSrcFromArrays, compare } from './test-utils';
import { Observable } from 'rxjs';
import { share, tap } from 'rxjs/operators';
import { assert } from '../lib/utils/assert';
import { packSegments, readSegsSequentially } from './segments-test-utils';
import { sourceFromArray } from './array-backed-byte-streaming';

function startProcessingWriteEvents(
	enc$: Observable<EncrEvent>, base: ObjSource|undefined
): Promise<{ header: Uint8Array; allSegs: Uint8Array; }> {
	let header: Uint8Array;
	let layout: Layout;
	let segs: SegEncrEvent[] = [];
	return enc$.pipe(
		tap(ev => {
			if (ev.type === 'header') {
				header = ev.header;
				layout = ev.layout;
			} else if (ev.type === 'seg') {
				segs.push(ev);
			} else {
				throw new Error(`Unknown encryption event type`);
			}
		})
	).toPromise()
	.then(async () => {
		if (layout.sections.length === 0) {
			if (segs.length !== 0) { throw new Error(
				`Layout has zero length, while there are new segments`); }
			return { header, allSegs: new Uint8Array(0) };
		}

		segs.sort((a, b) => {
			const aStart = a.segInfo.packedOfs;
			const aEnd = aStart + a.segInfo.packedLen;
			const bStart = b.segInfo.packedOfs;
			const bEnd = bStart + b.segInfo.packedLen;
			if (aEnd <= bStart) { return -1; }
			if (bEnd <= aStart) { return 1; }
			throw new Error(`Have an overlapping segments`);
		});

		// we'll use layout to find total packed length that may include base
		// sections, this allows to perform checks of layout array object
		let totalLen = ((layout.sections.length === 0) ?
			0 : layout.sections[layout.sections.length-1].ofs);
		for (let i=0; i<layout.sections.length; i+=1) {
			const chunk = layout.sections[i];
			if (chunk.src === 'new') {
				if (chunk.len === undefined) {
					if ((i+1) < layout.sections.length) { throw new Error(
						`Layout chunk with undefined length is not the last chunk in the layout`); }
					const lastNewSeg = segs[segs.length-1];
					totalLen = lastNewSeg.segInfo.packedOfs + lastNewSeg.segInfo.packedLen;
				} else {
					assert(chunk.len > 0);
					totalLen += chunk.len;
				}
			} else if (chunk.src === 'base') {
				if (!base) { throw new Error(
					`Layout has base section, while there is no base given`); }
				assert(chunk.len > 0);
				totalLen += chunk.len;
			} else {
				throw new Error(`Unknown value of src field in layout info`);
			}
		}

		const allSegs = new Uint8Array(totalLen);

		// write new segments
		for (const s of segs) {
			allSegs.set(s.seg, s.segInfo.packedOfs);
		}

		// add base bytes, if there are any
		if (base) {
			for (const chunk of layout.sections) {
				if (chunk.src !== 'base') { continue; }
				const baseChunk = await base.segSrc.readAt(
					chunk.baseOfs, chunk.len
				);
				if (!baseChunk
				|| (baseChunk.length !== chunk.len)) { throw new Error(
					`Not enough base segment bytes`); }
				allSegs.set(baseChunk, chunk.ofs);
			}
		}

		return { header, allSegs };
	});
}

export async function makeStreamSink(
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	payloadFormat: number, cryptor: AsyncSBoxCryptor, workLabel: number,
	base: ObjSource|undefined
): Promise<{ byteSink: ByteSink;
		completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }> }> {
	const segWriter = await makeSegmentsWriter(
		key, zerothNonce,
		(base ? base.version + 1 : version),
		(base ?
			{ type: 'update', base, payloadFormat } :
			{ type: 'new', segSize: 16, payloadFormat }),
		getRandom, cryptor, workLabel
	);
	const { sink, sub } = makeEncryptingByteSink(segWriter);
	const enc$ = Observable.create(sub).pipe(share());
	const completion = startProcessingWriteEvents(enc$, base);
	return { byteSink: sink, completion };
}

export async function compareContent(
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	completion: Promise<{ header: Uint8Array; allSegs: Uint8Array; }>,
	expectation: Uint8Array, cryptor: AsyncSBoxCryptor, workLabel: number
): Promise<void> {
	const { header, allSegs } = await completion;
	const segReader = await makeSegmentsReader(
		key, zerothNonce, version, header, cryptor, workLabel
	);
	const decrContent = await readSegsSequentially(segReader, allSegs);
	compare(decrContent, expectation);
}

export async function packedBytesToSrc(
	version: number,
	packedBytes: Promise<{ header: Uint8Array; allSegs: Uint8Array; }>
): Promise<ObjSource> {
	const { header, allSegs } = await packedBytes;
	return objSrcFromArrays(version, header, allSegs);
}

export async function encryptContent(
	content: Uint8Array,
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	payloadFormat: number, cryptor: AsyncSBoxCryptor, workLabel: number
): Promise<{ header: Uint8Array; seekableSegsSrc: ByteSource; }> {
	const segWriter = await makeSegmentsWriter(
		key, zerothNonce, version,
		{ type: 'new', segSize: 16, payloadFormat },
		getRandom, cryptor, workLabel
	);
	segWriter.setContentLength(content.length);
	const header = await segWriter.packHeader();
	const allSegs = await packSegments(segWriter, content);
	const seekableSegsSrc = sourceFromArray(allSegs);
	return { header, seekableSegsSrc };
}

export async function packToObjSrc(
	content: Uint8Array,
	key: Uint8Array, zerothNonce: Uint8Array, version: number,
	payloadFormat: number, cryptor: AsyncSBoxCryptor, workLabel: number
): Promise<ObjSource> {
	const { header, seekableSegsSrc: segSrc } = await encryptContent(
		content, key, zerothNonce, version, payloadFormat, cryptor, workLabel
	);
	return {
		version,
		readHeader: async () => header,
		segSrc
	};
}
