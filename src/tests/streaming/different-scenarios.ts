/*
 Copyright (C) 2020, 2022 3NSoft Inc.
 
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

import { itAsync, beforeAllAsync } from '../../test-lib/async-jasmine';
import { mockCryptor, getRandom } from '../../test-lib/test-utils';
import { KEY_LENGTH, NONCE_LENGTH, ObjSource } from '../../lib';
import { makeStreamSink, compareContent, packToObjSrc } from '../../test-lib/streams-test-utils';
import { EMPTY_BUFFER } from '../../lib/utils/buffer-utils';
import { joinByteArrs } from '../../test-lib/buffer-utils';

const cryptor = mockCryptor();

describe(`Empty base file`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	let baseSrc: ObjSource;
	const workLabel = 42;

	const payloadFormat = 2;

	beforeAllAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
		baseSrc = await packToObjSrc(
			EMPTY_BUFFER, key, zerothNonce, 1, payloadFormat, cryptor, workLabel
		);
	});

	itAsync(`new version, but still empty content`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat, cryptor, workLabel,
			baseSrc
		);
		await byteSink.done();
		await compareContent(
			key, zerothNonce, newVersion, completion, EMPTY_BUFFER,
			cryptor, workLabel
		);
	});

	itAsync(`new version, and new content in few slices`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat, cryptor, workLabel,
			baseSrc
		);
		const newContent = await getRandom(10000);
		let ofs=0;
		while (ofs<newContent.length) {
			const chunk = newContent.subarray(ofs, ofs + 300);
			await byteSink.spliceLayout(ofs, 0, chunk.length);
			await byteSink.write(ofs, chunk);
			ofs += chunk.length;
		}
		await byteSink.done();
		await compareContent(
			key, zerothNonce, newVersion, completion, newContent,
			cryptor, workLabel
		);
	});

	itAsync(`new version, and new content in one`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat, cryptor, workLabel,
			baseSrc
		);
		const newContent = await getRandom(100);
		await byteSink.spliceLayout(0, newContent.length, newContent.length);
		await byteSink.write(0, newContent);
		await byteSink.done();
		await compareContent(
			key, zerothNonce, newVersion, completion, newContent,
			cryptor, workLabel
		);
	});

});

describe(`Non-empty base file`, () => {

	let key: Uint8Array;
	let zerothNonce: Uint8Array;
	let baseContent: Uint8Array;
	let baseSrc: ObjSource;
	const workLabel = 42;

	const payloadFormat = 2;

	beforeAllAsync(async () => {
		key = await getRandom(KEY_LENGTH);
		zerothNonce = await getRandom(NONCE_LENGTH);
		baseContent = await getRandom(15000);
		baseSrc = await packToObjSrc(
			baseContent, key, zerothNonce, 1, payloadFormat, cryptor, workLabel
		);
	});

	itAsync(`cut base's tail and write no new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat,
			cryptor, workLabel, baseSrc
		);
		await byteSink.setSize(10000);
		await byteSink.done();
		await compareContent(
			key, zerothNonce, newVersion, completion,
			baseContent.subarray(0, 10000), cryptor, workLabel);
	});

	itAsync(`cut base's tail and insert new bytes into existing bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat,
			cryptor, workLabel, baseSrc
		);
		const newContent = await getRandom(10000);
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
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 1000),
			newContent,
			baseContent.subarray(1000, 10000)
		]);
		await compareContent(
			key, zerothNonce, newVersion, completion, expectedContent,
			cryptor, workLabel
		);
	});

	itAsync(`cut base's tail and append new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat,
			cryptor, workLabel, baseSrc
		);
		const newContent = await getRandom(10000);
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
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 1000),
			newContent
		]);
		await compareContent(
			key, zerothNonce, newVersion, completion, expectedContent,
			cryptor, workLabel
		);
	});

	itAsync(`splice base and append new bytes`, async () => {
		const newVersion = baseSrc.version + 1;
		const { byteSink, completion } = await makeStreamSink(
			key, zerothNonce, newVersion, payloadFormat,
			cryptor, workLabel, baseSrc
		);
		const newContent = await getRandom(10000);
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
		await byteSink.done();
		const expectedContent = joinByteArrs([
			baseContent.subarray(0, 3000),
			baseContent.subarray(8000),
			newContent
		]);
		await compareContent(
			key, zerothNonce, newVersion, completion, expectedContent,
			cryptor, workLabel
		);
	});

});
