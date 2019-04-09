/*
 Copyright(c) 2015 - 2018 3NSoft Inc.
 
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

export { LocationInSegment, SegmentInfo, SegId } from './segments/xsp-info';
export { SegmentsReader, makeSegmentsReader } from './segments/reader';
export { SegmentsWriter, makeSegmentsWriter, WritableSegmentInfo,
	NewSegmentInfo, BaseSegmentInfo }
	from './segments/writer';
export { ObjSource, ByteSource, ByteSink, Observer, idToHeaderNonce,
	Layout, LayoutBaseSection, LayoutNewSection }
	from './streaming/common';
export { makeDecryptedByteSource } from './streaming/decrypting-byte-src';
export { makeEncryptingByteSink, EncrEvent, HeaderEncrEvent, SegEncrEvent,
	Subscribe }
	from './streaming/encrypting-byte-sink';
export { makeEncryptingObjSource, makeObjSourceFromArrays }
	from './streaming/encrypting-obj-src';
export { AsyncSBoxCryptor, KEY_LENGTH, NONCE_LENGTH, POLY_LENGTH,
	compareVectors, calculateNonce, advanceNonce }
	from './utils/crypt-utils';

Object.freeze(exports);