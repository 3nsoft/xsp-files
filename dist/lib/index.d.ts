import { arrays, secret_box as sbox } from 'ecma-nacl';
export interface LocationInSegment {
    /**
     * Is a position in a decrypted content of a segment.
     */
    pos: number;
    /**
     * Segment with a loaction of interest.
     */
    seg: {
        /**
         * Index that points to the segment in the file.
         */
        ind: number;
        /**
         * Segment's start in the encrypted file.
         */
        start: number;
        /**
         * Length of encrypted segment.
         */
        len: number;
    };
}
export interface SegmentsReader {
    /**
     * @param pos is byte's position index in file content.
     * @return corresponding location in segment with segment's info.
     */
    locationInSegments(pos: number): LocationInSegment;
    /**
     * @param seg is an array with encrypted segment's bytes, starting at
     * zeroth index. Array may be longer than a segment, but it will an error,
     * if it is shorter.
     * @param segInd is segment's index in file.
     * @return decrypted content bytes of a given segment and a length of
     * decrypted segment.
     * Data array is a view of buffer, which has 32 zeros preceding
     * content bytes.
     */
    openSeg(seg: Uint8Array, segInd: number): {
        data: Uint8Array;
        segLen: number;
        last?: boolean;
    };
    /**
     * This wipes file key and releases used resources.
     */
    destroy(): void;
    isEndlessFile(): boolean;
    contentLength(): number;
    segmentsLength(): number;
    segmentSize(segInd: number): number;
    numberOfSegments(): number;
}
export interface SegmentsWriter {
    /**
     * @param pos is byte's position index in file content.
     * @return corresponding location in segment with segment's info.
     */
    locationInSegments(pos: number): LocationInSegment;
    packSeg(content: Uint8Array, segInd: number): {
        dataLen: number;
        seg: Uint8Array;
    };
    /**
     * This wipes file key and releases used resources.
     */
    destroy(): void;
    /**
     * This resets writer's internal state, keeping a file key, and removes info
     * about segment chains, total length, etc.
     * This allows for 100% fresh write of segments with the same file key, and
     * same default segment size.
     */
    reset(): void;
    packHeader(): Uint8Array;
    setContentLength(totalContentLen: number): void;
    isHeaderModified(): boolean;
    splice(pos: number, rem: number, ins: number): any;
    isEndlessFile(): boolean;
    contentLength(): number;
    segmentsLength(): number;
    segmentSize(segInd: number): number;
    numberOfSegments(): number;
}
/**
 * This is a starting sequence of xsp file, which contains both
 * encrypted segments and a header.
 */
export declare var FILE_START: Uint8Array;
/**
 * This is an offset to segments in xsp file with both segments and header.
 */
export declare var SEGMENTS_OFFSET: number;
/**
 * This is a starting sequence of a file with a header only.
 */
export declare var HEADER_FILE_START: Uint8Array;
/**
 * This is a starting sequence of a file with encrypted segments nly.
 */
export declare var SEGMENTS_FILE_START: Uint8Array;
/**
 * @param segsLen is a total length of encrypted segments.
 * @return XSP file starting bytes, which are
 * (1) 3 bytes "xsp", (2) 8 bytes with an offset, at which header starts.
 */
export declare function generateXSPFileStart(segsLen: number): Uint8Array;
export declare function getXSPHeaderOffset(xspBytes: Uint8Array): number;
export interface FileKeyHolder {
    /**
     * @param segSizein256bs is a default segment size in 256-byte blocks
     * @param randomBytes is a function that produces cryptographically strong
     * random numbers (bytes).
     * @return segments writer either for a new file, or for a complete
     * replacement of existing file's bytes.
     */
    newSegWriter(segSizein256bs: number, randomBytes: (n: number) => Uint8Array): SegmentsWriter;
    /**
     * @param header is an array with file's header. Array must contain only
     * header's bytes, as its length is used to decide how to process it.
     * @param randomBytes is a function that produces cryptographically strong
     * random numbers (bytes).
     * @return segments writer for changing existing file.
     */
    segWriter(header: Uint8Array, randomBytes: (n: number) => Uint8Array): SegmentsWriter;
    /**
     * @param header is an array with file's header. Array must contain only
     * header's bytes, as its length is used to decide how to process it.
     * @return segment reader
     */
    segReader(header: Uint8Array): SegmentsReader;
    /**
     * This wipes file key and releases used resources.
     */
    destroy(): void;
    /**
     * @param (optional) array factory for use by cloned key holder.
     * @return creates a clone of this key holder, cloning key and all internals.
     */
    clone(arrFactory?: arrays.Factory): FileKeyHolder;
}
/**
 * @param mkeyEncr master key encryptor, which is used to make file key pack.
 * @param randomBytes is a function that produces cryptographically strong
 * random numbers (bytes).
 * @param arrFactory (optional) array factory
 * @return file key holder with a newly generated key.
 */
export declare function makeNewFileKeyHolder(mkeyEncr: sbox.Encryptor, randomBytes: (n: number) => Uint8Array, arrFactory?: arrays.Factory): FileKeyHolder;
/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
export declare function makeFileKeyHolder(mkeyDecr: sbox.Decryptor, header: Uint8Array, arrFactory?: arrays.Factory): FileKeyHolder;
