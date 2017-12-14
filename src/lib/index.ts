/* Copyright(c) 2015 - 2017 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

export { LocationInSegment } from './segments/xsp-info';
export { SegmentsReader, makeSegmentsReader } from './segments/reader';
export { SegmentsWriter, makeSegmentsWriter, makeSplicingSegmentsWriter }
	from './segments/writer';
export { AsyncSBoxCryptor, KEY_LENGTH, NONCE_LENGTH, POLY_LENGTH,
	compareVectors, calculateNonce, advanceNonce }
	from './crypt-utils';

Object.freeze(exports);