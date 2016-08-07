import { arrays } from 'ecma-nacl';
import { LocationInSegment, SegInfoHolder } from './xsp-info';
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
export declare class SegWriter extends SegInfoHolder implements SegmentsWriter {
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
    wrap(): SegmentsWriter;
}
