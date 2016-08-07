import { arrays } from 'ecma-nacl';
import { LocationInSegment, SegInfoHolder } from './xsp-info';
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
export declare class SegReader extends SegInfoHolder implements SegmentsReader {
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
    wrap(): SegmentsReader;
}
