/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";
var file_regalia_1 = require('./file-regalia');
exports.generateXSPFileStart = file_regalia_1.generateXSPFileStart;
exports.getXSPHeaderOffset = file_regalia_1.getXSPHeaderOffset;
exports.FILE_START = file_regalia_1.FILE_START;
exports.HEADER_FILE_START = file_regalia_1.HEADER_FILE_START;
exports.SEGMENTS_FILE_START = file_regalia_1.SEGMENTS_FILE_START;
exports.SEGMENTS_OFFSET = file_regalia_1.SEGMENTS_OFFSET;
var key_holder_1 = require('./key-holder');
exports.makeFileKeyHolder = key_holder_1.makeFileKeyHolder;
exports.makeNewFileKeyHolder = key_holder_1.makeNewFileKeyHolder;
exports.makeHolderFor = key_holder_1.makeHolderFor;
Object.freeze(exports);
