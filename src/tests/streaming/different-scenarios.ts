/*
 Copyright (C) 2020 3NSoft Inc.
 
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

import { itAsync, beforeAllAsync } from '../../test-lib/async-jasmine';
import { mockCryptor, getRandom } from '../../test-lib/test-utils';
import { KEY_LENGTH, NONCE_LENGTH, ObjSource } from '../../lib';
import { packAttrsAndConentAsObjSource, makeStreamSinkWithAttrs, compareContentAndAttrs } from '../../test-lib/streams-test-utils';
import { EMPTY_BUFFER } from '../../lib/utils/buffer-utils';
import { joinByteArrs } from '../../test-lib/buffer-utils';

const cryptor = mockCryptor();

describe(`Empty base file with attributes`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	let baseAttrs: Uint8Array;
	let baseSrc: ObjSource;
	let newAttrs: Uint8Array;

	beforeAllAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
		baseAttrs = await getRandom(21);
		baseSrc = await packAttrsAndConentAsObjSource(
			baseAttrs, EMPTY_BUFFER, key, zerothNonce, 1, cryptor);
		newAttrs = await getRandom(baseAttrs.length);
	});

	itAsync(`new version with same size attributes, but still empty content`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		await byteSink.setAttrSectionSize(newAttrs.length);
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion, EMPTY_BUFFER, newAttrs,
			cryptor);
	});

	itAsync(`new version with same size with attributes, and new content`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		let ofs=0;
		while (ofs<newContent.length) {
			const chunk = newContent.subarray(ofs, ofs + 300);
			await byteSink.spliceLayout(ofs, 0, chunk.length);
			await byteSink.write(ofs, chunk);
			ofs += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			newContent, newAttrs,
			cryptor);
	});

});

describe(`Non-empty base file with attrs`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	let baseAttrs: Uint8Array;
	let baseContent: Uint8Array;
	let baseSrc: ObjSource;
	let newAttrs: Uint8Array;

	beforeAllAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
		baseAttrs = await getRandom(21);
		baseContent = await getRandom(15000);
		baseSrc = await packAttrsAndConentAsObjSource(
			baseAttrs, baseContent, key, zerothNonce, 1, cryptor);
		newAttrs = await getRandom(baseAttrs.length);
	});

	itAsync(`cut base's tail and write no new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		await byteSink.setAttrSectionSize(newAttrs.length);
		await byteSink.setSize(10000);
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			baseContent.subarray(0, 10000), newAttrs,
			cryptor);
	});

	itAsync(`cut base's tail and insert new bytes into existing bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		await byteSink.setSize(10000);
		let ofsInNew = 0;
		let ofsInSink = 1000;
		while (ofsInNew<newContent.length) {
			const chunk = newContent.subarray(ofsInNew, ofsInNew + 1201);
			await byteSink.spliceLayout(ofsInSink, 0, chunk.length);
			await byteSink.write(ofsInSink, chunk);
			ofsInNew += chunk.length;
			ofsInSink += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 1000),
			newContent,
			baseContent.subarray(1000, 10000)
		]);
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			expectedContent, newAttrs,
			cryptor);
	});

	itAsync(`cut base's tail and append new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		let ofsInSink = 1000;
		await byteSink.setSize(ofsInSink);
		let ofsInNew = 0;
		while (ofsInNew<newContent.length) {
			const chunk = newContent.subarray(ofsInNew, ofsInNew + 1201);
			await byteSink.setSize(ofsInSink + chunk.length);
			await byteSink.write(ofsInSink, chunk);
			ofsInNew += chunk.length;
			ofsInSink += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 1000),
			newContent
		]);
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			expectedContent, newAttrs,
			cryptor);
	});

	itAsync(`cut base's tail and insert append new bytes via splice`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		let ofsInSink = 1000;
		await byteSink.setSize(ofsInSink);
		let ofsInNew = 0;
		while (ofsInNew<newContent.length) {
			const chunk = newContent.subarray(ofsInNew, ofsInNew + 1201);
			await byteSink.spliceLayout(ofsInSink, 0, chunk.length);
			await byteSink.write(ofsInSink, chunk);
			ofsInNew += chunk.length;
			ofsInSink += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 1000),
			newContent
		]);
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			expectedContent, newAttrs,
			cryptor);
	});

	itAsync(`splice base and append new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		await byteSink.spliceLayout(3000, 5000, 0);
		let ofsInSink = 10000;
		let ofsInNew = 0;
		while (ofsInNew<newContent.length) {
			const chunk = newContent.subarray(ofsInNew, ofsInNew + 1201);
			await byteSink.setSize(ofsInSink + chunk.length);
			await byteSink.write(ofsInSink, chunk);
			ofsInNew += chunk.length;
			ofsInSink += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 3000),
			baseContent.subarray(8000),
			newContent
		]);
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			expectedContent, newAttrs,
			cryptor);
	});

	itAsync(`splice base and insert append new bytes via splice`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSinkWithAttrs(
			key, zerothNonce, newVersion, cryptor,
			{ src: baseSrc, attrSize: baseAttrs.length });
		const newContent = await getRandom(10000);
		await byteSink.setAttrSectionSize(newAttrs.length);
		await byteSink.spliceLayout(3000, 5000, 0);
		let ofsInSink = 10000;
		let ofsInNew = 0;
		while (ofsInNew<newContent.length) {
			const chunk = newContent.subarray(ofsInNew, ofsInNew + 1201);
			await byteSink.spliceLayout(ofsInSink, 0, chunk.length);
			await byteSink.write(ofsInSink, chunk);
			ofsInNew += chunk.length;
			ofsInSink += chunk.length;
		}
		await byteSink.writeAttrs(newAttrs);
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 3000),
			baseContent.subarray(8000),
			newContent
		]);
		await compareContentAndAttrs(
			key, zerothNonce, newVersion, completion,
			expectedContent, newAttrs,
			cryptor);
	});

});
