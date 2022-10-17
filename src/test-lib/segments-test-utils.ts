/*
 Copyright(c) 2013 - 2018, 2020 3NSoft Inc.
 
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

import { SegmentsReader, SegmentsWriter, ByteSource } from '../lib/index';
import { writerToArray } from './array-backed-byte-streaming';

export async function packSegments(
	writer: SegmentsWriter, data: Uint8Array, baseSegs?: ByteSource
): Promise<Uint8Array> {
	if (writer.hasBase && !baseSegs) { throw new Error(
		`Source of base segments is not given for packing with writer that has base`); }
	const { completeArray: segs, writer: arrWriter } = writerToArray();
	await arrWriter.setSize(writer.segmentsLength);
	let dataOfs = 0;
	for (const s of writer.segmentInfos()) {
		let pos = s.packedOfs;
		let bytes: Uint8Array;
		if (s.type === 'base') {
			expect(s.baseOfs).toBeGreaterThanOrEqual(0);
			await baseSegs!.seek(s.baseOfs!);
			bytes = (await baseSegs!.readNext(s.packedLen))!;
		} else if (s.type === 'new') {
			expect(s.needPacking).toBe(true);
			const dataToPack = data.subarray(dataOfs, dataOfs+s.contentLen);
			dataOfs += dataToPack.length;
			if (s.endlessChain) {
				if (dataToPack.length === 0) { break; }
				bytes = await writer.packSeg(dataToPack, s);
				const isLastSeg = (bytes.length < s.packedLen);
				if (isLastSeg) {
					await arrWriter.write(pos, bytes);
					break;
				}
			} else {
				bytes = await writer.packSeg(dataToPack, s);
			}
		} else {
			throw new Error(`Shouldn't get here`);
		}
		expect(bytes.length).toBe(s.packedLen);
		await arrWriter.write(pos, bytes);
	}
	expect(writer.areSegmentsPacked).toBeTruthy(
		`not all segments are packed in ${writer.isEndlessFile ? 'endless' : 'finite'} file`);
	await arrWriter.done();
	return await segs;
}

export async function readSegsSequentially(
	reader: SegmentsReader, allSegs: Uint8Array
): Promise<Uint8Array> {
	const contentLength = reader.contentLength;
	const { completeArray: data, writer: arrWriter } = writerToArray();
	await arrWriter.setSize(contentLength);
	if (contentLength === undefined) {
		for (const segInfo of reader.segmentInfos()) {
			const segBytes = allSegs.subarray(
				segInfo.packedOfs, segInfo.packedOfs + segInfo.packedLen);
			if (segBytes.length === 0) { break; }
			const isLastSeg = (segBytes.length < segInfo.packedLen);
			const segContent = await reader.openSeg(segInfo, segBytes);
			if (isLastSeg) {
				expect(segContent.length).toBeLessThan(segInfo.contentLen);
			} else {
				expect(segContent.length).toBe(segInfo.contentLen);
			}
			await arrWriter.write(segInfo.contentOfs, segContent);
			if (isLastSeg) { break; }
		}
	} else {
		for (const segInfo of reader.segmentInfos()) {
			const segBytes = allSegs.subarray(
				segInfo.packedOfs, segInfo.packedOfs + segInfo.packedLen);
			const segContent = await reader.openSeg(segInfo, segBytes);
			expect(segInfo.contentLen).toBe(segContent.length);
			await arrWriter.write(segInfo.contentOfs, segContent);
		}
	}
	await arrWriter.done();
	return await data;
}
