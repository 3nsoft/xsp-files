/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";
const ecma_nacl_1 = require('ecma-nacl');
const writer_1 = require('./segments/writer');
const reader_1 = require('./segments/reader');
const binding_1 = require('./binding');
var KEY_PACK_LENGTH = 72;
class KeyHolder {
    constructor(key, keyPack, arrFactory) {
        this.key = key;
        this.keyPack = keyPack;
        this.arrFactory = (arrFactory ?
            arrFactory : ecma_nacl_1.arrays.makeFactory());
        Object.seal(this);
    }
    reencryptKey(encr) {
        this.keyPack = encr.pack(this.key);
    }
    newSegWriter(segSizein256bs, randomBytes) {
        var writer = new writer_1.SegWriter(this.key, this.keyPack, null, segSizein256bs, randomBytes, this.arrFactory);
        return writer.wrap();
    }
    segWriter(header, randomBytes) {
        var writer = new writer_1.SegWriter(this.key, new Uint8Array(header.subarray(0, KEY_PACK_LENGTH)), header.subarray(KEY_PACK_LENGTH), null, randomBytes, this.arrFactory);
        return writer.wrap();
    }
    segReader(header) {
        var reader = new reader_1.SegReader(this.key, header.subarray(KEY_PACK_LENGTH), this.arrFactory);
        return reader.wrap();
    }
    destroy() {
        if (this.key) {
            ecma_nacl_1.arrays.wipe(this.key);
            this.key = null;
        }
        this.keyPack = null;
        if (this.arrFactory) {
            this.arrFactory.wipeRecycled();
            this.arrFactory = null;
        }
    }
    clone(arrFactory) {
        var key = new Uint8Array(this.key.length);
        key.set(this.key);
        var kh = new KeyHolder(key, this.keyPack, arrFactory);
        return kh.wrap();
    }
    wrap() {
        var wrap = {
            destroy: binding_1.bind(this, this.destroy),
            reencryptKey: binding_1.bind(this, this.reencryptKey),
            newSegWriter: binding_1.bind(this, this.newSegWriter),
            segWriter: binding_1.bind(this, this.segWriter),
            segReader: binding_1.bind(this, this.segReader),
            clone: binding_1.bind(this, this.clone)
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
function makeNewFileKeyHolder(mkeyEncr, randomBytes, arrFactory) {
    var fileKey = randomBytes(ecma_nacl_1.secret_box.KEY_LENGTH);
    var fileKeyPack = mkeyEncr.pack(fileKey);
    var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
    return kh.wrap();
}
exports.makeNewFileKeyHolder = makeNewFileKeyHolder;
/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
function makeFileKeyHolder(mkeyDecr, header, arrFactory) {
    var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
    var fileKey = mkeyDecr.open(fileKeyPack);
    var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
    return kh.wrap();
}
exports.makeFileKeyHolder = makeFileKeyHolder;
Object.freeze(exports);
