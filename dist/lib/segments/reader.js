/* Copyright(c) 2015 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";
const ecma_nacl_1 = require("ecma-nacl");
const xsp_info_1 = require("./xsp-info");
const binding_1 = require("../binding");
class SegReader extends xsp_info_1.SegInfoHolder {
    constructor(key, header, arrFactory) {
        super();
        this.arrFactory = arrFactory;
        if (key.length !== ecma_nacl_1.secret_box.KEY_LENGTH) {
            throw new Error("Given key has wrong size.");
        }
        this.key = new Uint8Array(key);
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
        Object.seal(this);
    }
    openSeg(seg, segInd) {
        var isLastSeg = ((segInd + 1) === this.totalNumOfSegments);
        var nonce = this.getSegmentNonce(segInd, this.arrFactory);
        var segLen = this.segmentSize(segInd);
        if (seg.length < segLen) {
            if (this.isEndlessFile()) {
                isLastSeg = true;
            }
            else {
                throw new Error("Given byte array is smaller than segment's size.");
            }
        }
        else if (seg.length > segLen) {
            seg = seg.subarray(0, segLen);
        }
        var bytes = ecma_nacl_1.secret_box.open(seg, nonce, this.key, this.arrFactory);
        this.arrFactory.recycle(nonce);
        this.arrFactory.wipeRecycled();
        return { data: bytes, segLen: segLen, last: isLastSeg };
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
    wrap() {
        var wrap = {
            locationInSegments: binding_1.bind(this, this.locationInSegments),
            openSeg: binding_1.bind(this, this.openSeg),
            destroy: binding_1.bind(this, this.destroy),
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
exports.SegReader = SegReader;
Object.freeze(SegReader.prototype);
Object.freeze(SegReader);
Object.freeze(exports);
