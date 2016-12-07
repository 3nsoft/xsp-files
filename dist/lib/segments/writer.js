/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";
const ecma_nacl_1 = require("ecma-nacl");
const xsp_info_1 = require("./xsp-info");
const binding_1 = require("../binding");
class SegWriter extends xsp_info_1.SegInfoHolder {
    /**
     * @param key
     * @param packedKey
     * @param header a file's header without (!) packed key's 72 bytes.
     * Array must contain only header's bytes, as its length is used to decide
     * how to process it. It should be undefined for a new writer.
     * @param segSizein256bs should be present for a new writer,
     * otherwise, be undefined.
     * @param randomBytes
     * @param arrFactory
     */
    constructor(key, packedKey, header, segSizein256bs, randomBytes, arrFactory) {
        super();
        this.arrFactory = arrFactory;
        this.randomBytes = randomBytes;
        if (key.length !== ecma_nacl_1.secret_box.KEY_LENGTH) {
            throw new Error("Given key has wrong size.");
        }
        this.key = new Uint8Array(key);
        if (packedKey.length !== 72) {
            throw new Error("Given file key pack has wrong size.");
        }
        this.packedKey = packedKey;
        if (header) {
            if (header.length === 65) {
                this.initForEndlessFile(header, this.key, this.arrFactory);
            }
            else {
                if ((((header.length - 46) % 30) !== 0) ||
                    (header.length < 46)) {
                    throw new Error("Given header array has incorrect size.");
                }
                this.initForFiniteFile(header, this.key, this.arrFactory);
            }
            this.headerModified = false;
        }
        else if ('number' === typeof segSizein256bs) {
            if ((segSizein256bs < 1) || (segSizein256bs > 255)) {
                throw new Error("Given segment size is illegal.");
            }
            this.initOfNewWriter(segSizein256bs << 8);
            this.headerModified = true;
        }
        else {
            throw new Error("Arguments are illegal, both header bytes and " +
                "segment size are missing");
        }
        Object.seal(this);
    }
    initOfNewWriter(segSize) {
        this.segSize = segSize;
        this.totalContentLen = undefined;
        this.totalNumOfSegments = undefined;
        this.totalSegsLen = undefined;
        this.segChains = [{
                numOfSegs: undefined,
                lastSegSize: undefined,
                nonce: this.randomBytes(24)
            }];
    }
    packSeg(content, segInd) {
        var nonce = this.getSegmentNonce(segInd, this.arrFactory);
        var expectedContentSize = this.segmentSize(segInd) - 16;
        if (content.length < expectedContentSize) {
            if (!this.isEndlessFile()) {
                throw new Error("Given content has length " + content.length +
                    ", while content length of segment " + segInd +
                    " should be " + expectedContentSize);
            }
        }
        else if (content.length > expectedContentSize) {
            content = content.subarray(0, expectedContentSize);
        }
        var seg = ecma_nacl_1.secret_box.pack(content, nonce, this.key, this.arrFactory);
        this.arrFactory.recycle(nonce);
        this.arrFactory.wipeRecycled();
        return { seg: seg, dataLen: content.length };
    }
    destroy() {
        this.arrFactory.wipe(this.key);
        this.key = undefined;
        for (var i = 0; i < this.segChains.length; i += 1) {
            this.arrFactory.wipe(this.segChains[i].nonce);
        }
        this.segChains = undefined;
        this.arrFactory = undefined;
    }
    reset() {
        this.initOfNewWriter(this.segSize);
        this.headerModified = true;
    }
    packHeader() {
        // pack head
        var head = this.packInfoToBytes();
        // encrypt head with a file key
        head = ecma_nacl_1.secret_box.formatWN.pack(head, this.randomBytes(24), this.key, this.arrFactory);
        // assemble and return complete header byte array
        var completeHeader = new Uint8Array(this.packedKey.length + head.length);
        completeHeader.set(this.packedKey, 0);
        completeHeader.set(head, 72);
        this.headerModified = false;
        return completeHeader;
    }
    setContentLength(totalSegsLen) {
        super.setContentLength(totalSegsLen);
        this.headerModified = true;
    }
    isHeaderModified() {
        return this.headerModified;
    }
    splice(pos, rem, ins) {
        if (this.isEndlessFile()) {
            throw new Error("Cannot splice endless file");
        }
        if (((rem < 1) && (ins < 1)) || (rem < 0) || (ins < 0)) {
            throw new Error("Invalid modification parameters.");
        }
        if ((this.totalSegsLen - rem + ins) > 0xffffffffffff) {
            throw new Error("Given modification will make file too long.");
        }
        var startLoc = this.locationInSegments(pos);
        // TODO change segments info, and return info above required
        //      (re)encryption.
        throw new Error("Code is incomplete");
        // - calculate locations of edge bytes.
        var remEnd;
        if (rem > 0) {
        }
        // return object with info for getting bytes, and a lambda() to effect
        // the change, which should be called after reading edge bytes.
        return {};
    }
    wrap() {
        var wrap = {
            locationInSegments: binding_1.bind(this, this.locationInSegments),
            packSeg: binding_1.bind(this, this.packSeg),
            packHeader: binding_1.bind(this, this.packHeader),
            setContentLength: binding_1.bind(this, this.setContentLength),
            splice: binding_1.bind(this, this.splice),
            isHeaderModified: binding_1.bind(this, this.isHeaderModified),
            destroy: binding_1.bind(this, this.destroy),
            reset: binding_1.bind(this, this.reset),
            isEndlessFile: binding_1.bind(this, this.isEndlessFile),
            contentLength: binding_1.bind(this, this.contentLength),
            segmentSize: binding_1.bind(this, this.segmentSize),
            segmentsLength: binding_1.bind(this, this.segmentsLength),
            numberOfSegments: binding_1.bind(this, this.numberOfSegments)
        };
        Object.freeze(wrap);
        return wrap;
    }
}
exports.SegWriter = SegWriter;
Object.freeze(SegWriter.prototype);
Object.freeze(SegWriter);
Object.freeze(exports);
