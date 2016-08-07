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
