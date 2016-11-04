/**
 * This file contains code for working with file headers and (un)packing
 * file segments.
 * Exported classes should be used inside xsp library, and must be wrapped,
 * if such functionality is needed externally.
 */
import { arrays } from 'ecma-nacl';
import * as xsp from './index';
export interface ChainedSegsInfo {
    nonce: Uint8Array;
    numOfSegs: number;
    lastSegSize: number;
}
export declare abstract class SegInfoHolder {
    /**
     * Total length of encrypted segments.
     * Endless file has this field set to null.
     */
    protected totalSegsLen: number;
    /**
     * Total length of content bytes in this file.
     * Endless file has this field set to null.
     */
    protected totalContentLen: number;
    /**
     * Total number of segment, for a fast boundary check.
     * Endless file has this field set to null.
     */
    protected totalNumOfSegments: number;
    /**
     * Common encrypted segment size.
     * Odd segments must be smaller than this value.
     */
    protected segSize: number;
    /**
     * Array with info objects about chains of segments with related nonces.
     * This array shall have zero elements, if file is empty.
     * If it is an endless file, then a single element shall have
     * first segments' nonce, while all other numeric fields shall be null.
     */
    protected segChains: ChainedSegsInfo[];
    /**
     * Use this methods in inheriting classes.
     * @param header is a 65 bytes of a with-nonce pack, containing
     * 1) 1 byte, indicating segment size in 256byte chuncks, and
     * 2) 24 bytes of the first segment's nonce.
     * @param key is this file's key
     * @param arrFactory
     */
    protected initForEndlessFile(header: Uint8Array, key: Uint8Array, arrFactory: arrays.Factory): void;
    /**
     * Use this methods in inheriting classes.
     * @param header is 46+n*30 bytes with-nonce pack, containing
     * 1) 5 bytes with total segments' length,
     * 2) 1 byte, indicating segment size in 256byte chuncks
     * 3) n 30-bytes chunks for each segments chain (n===0 for an empty file):
     * 3.1) 4 bytes with number of segments in this chain,
     * 3.2) 2 bytes with this chain's last segments size,
     * 3.3) 24 bytes with the first nonce in this chain.
     * @param key is this file's key
     * @param arrFactory
     */
    protected initForFiniteFile(header: Uint8Array, key: Uint8Array, arrFactory: arrays.Factory): void;
    isEndlessFile(): boolean;
    contentLength(): number;
    setContentLength(totalContentLen: number): void;
    /**
     * @param pos is byte's position index in file content.
     * @return corresponding location in segment with segment's info.
     */
    locationInSegments(pos: number): xsp.LocationInSegment;
    protected packInfoToBytes(): Uint8Array;
    /**
     * @param segInd
     * @return segment's nonce, recyclable after its use.
     */
    protected getSegmentNonce(segInd: number, arrFactory: arrays.Factory): Uint8Array;
    numberOfSegments(): number;
    segmentSize(segInd: number): number;
    segmentsLength(): number;
}
export declare class SegReader extends SegInfoHolder implements xsp.SegmentsReader {
    /**
     * This is a file key, which should be wipped, after this object
     * is no longer needed.
     */
    private key;
    private arrFactory;
    constructor(key: Uint8Array, header: Uint8Array, arrFactory: arrays.Factory);
    openSeg(seg: Uint8Array, segInd: number): {
        data: Uint8Array;
        segLen: number;
        last?: boolean;
    };
    destroy(): void;
    wrap(): xsp.SegmentsReader;
}
export declare class SegWriter extends SegInfoHolder implements xsp.SegmentsWriter {
    /**
     * This is a file key, which should be wipped, after this object
     * is no longer needed.
     */
    private key;
    /**
     * This is a part of header with encrypted file key.
     * The sole purpose of this field is to reuse these bytes on writting,
     * eliminated a need to have a master key encryptor every time, when
     * header is packed.
     */
    private packedKey;
    private arrFactory;
    private randomBytes;
    private headerModified;
    /**
     * @param key
     * @param packedKey
     * @param header a file's header without (!) packed key's 72 bytes.
     * Array must contain only header's bytes, as its length is used to decide
     * how to process it. It should be null for a new writer, and not-null,
     * when writer is based an existing file's structure.
     * @param segSizein256bs should be present for a new writer,
     * otherwise, be null.
     * @param randomBytes
     * @param arrFactory
     */
    constructor(key: Uint8Array, packedKey: Uint8Array, header: Uint8Array, segSizein256bs: number, randomBytes: (n: number) => Uint8Array, arrFactory: arrays.Factory);
    private initOfNewWriter(segSize);
    packSeg(content: Uint8Array, segInd: number): {
        dataLen: number;
        seg: Uint8Array;
    };
    destroy(): void;
    reset(): void;
    packHeader(): Uint8Array;
    setContentLength(totalSegsLen: number): void;
    isHeaderModified(): boolean;
    splice(pos: number, rem: number, ins: number): {};
    wrap(): xsp.SegmentsWriter;
}
