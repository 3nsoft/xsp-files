import { arrays, secret_box as sbox } from 'ecma-nacl';
import { SegmentsWriter } from './segments/writer';
import { SegmentsReader } from './segments/reader';
export interface FileKeyHolder {
    reencryptKey(encr: sbox.Encryptor): void;
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
