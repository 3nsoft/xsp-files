/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

export { LocationInSegment } from './segments/xsp-info';
export { SegmentsReader } from './segments/reader';
export { SegmentsWriter } from './segments/writer';

export { generateXSPFileStart, getXSPHeaderOffset,
	FILE_START, HEADER_FILE_START, SEGMENTS_FILE_START, SEGMENTS_OFFSET }
	from './file-regalia';

export { FileKeyHolder, makeFileKeyHolder, makeNewFileKeyHolder }
	from './key-holder';

Object.freeze(exports);