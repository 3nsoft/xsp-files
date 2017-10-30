# XSP format for NaCl-encrypted files (XSalsa+Poly).

XSP file format for objects encrypted with NaCl. 

## Get xsp-files

### NPM Package

This library is registered on
[npmjs.org](https://npmjs.org/package/xsp-files). To install it, do:

    npm install xsp-files

Package comes with already compiled library code in dist/ folder. For testing, bring up a build environment (see below), and run necessary [gulp](http://gulpjs.com/) tasks.

### Building

Once you get package, or this repo, do in the folder

    npm install

which will install dev-dependencies.

Building and testing is done via npm script.
Do in the folder

    npm run test

or

    npm run build

and have fun with it.

## XSP file format

Each NaCl's cipher must be read completely, before any plain text output.
Such requirement makes reading big files awkward.
Therefore, we need a file format, which satisfies the following requirements:

 * file should be split into segments;
 * it should be possible to randomly read segments;
 * segment should have poly+cipher, allowing to check segment's integrity;
 * it should be possible to randomly remove and add segments without re-encrypting the whole file;
 * segments' nonces should never be reused, even when performing partial changes to a file, without complete file re-encryption;
 * it should be possible to detect segment reshuffling;
 * there should be cryptographic proof of a complete file size, for files with
known size;
 * there should be a stream-like setting, where segments can be encrypted and read without knowledge of a final length;
 * when complete length of a stream is finally known, switching to known-length setting should be cheap.

We call this format XSP, to stand for XSalsa+Poly, to indicate that file layout
is specifically tailored for storing NaCl's secret box's ciphers.
XSP file has segments, which are NaCl's packs of Poly and XSalsa cipher, and a header.

Header can be of two types, distinguished by header's size.

### Endless file

65-byte header is used for a file with unknown length (endless file), and looks as follows:

    |<-          65 bytes          ->|
    +--------------------------------+
    | seg size | first segment nonce |
    +--------------------------------+
    |<-          WN format         ->|

 * Seg size is a single byte. Its value, times 256, gives segment's length. This sets a shortest segment to be 256 bytes, and sets a longest one to be 65280 bytes.
 * All segments have given size except for the last segment, which may be shorter.
 * Nonces for segments related to the initial nonce through delta, equal to segment's index, which starts from 0 for the first segment.

WN format here is that from ecma-nacl:

    +-------+ +------+ +---------------+
    | nonce | | poly | |  data cipher  |
    +-------+ +------+ +---------------+
    | <----       WN format      ----> |


Let's define a segment chain to be a series of segments, encrypted with related nonces.
Chain requires three parameters for a comfortable use:

 * first segment's nonce;
 * number of segments in the chain;
 * length of the last segment in the chain, which can be smaller than common segment length.

Endless file has only one segment chain, and both length of the last segment, and a number of segments cannot be known. 

### Finite file

(46+n*30)-byte header is used for a file with known length (finite file).
n is a number of segment chains in the file.
Header layout:

    |<-              46+n*30 bytes                ->|
    +-----------------------------------------------+
    | total segs length | | seg size | | seg chains |
    +-----------------------------------------------+
    |<-                WN format                  ->|

 * Total segments length, is just that. It excludes header and other file elements.
 * Total segments length is encoded big-endian way into 5 bytes, allowing up to 2^40-1 bytes, or 1TB - 1byte.
 * Content length is equal to total segments length minus 16*n, where n is a total number of segments (16 bytes is poly's code length).

Segment chain bytes look as following:

    |<-   4 bytes  ->| |<-  2 bytes  ->| |<-     24 bytes    ->|
    +----------------+ +---------------+ +---------------------+
    | number of segs | | last seg size | | first segment nonce |
    +----------------+ +---------------+ +---------------------+

### Object versions

Every object may go through many versions, and it would be nice have both object id and a version imprinted into package.
Imagine that a client wants to get a particular object and version from a server.
If server tries to give an incorrect version, it should be noticeable immediately.
XSP employs the following approach to this.

Header is a with-nonce package.
Nonce is some zeroth (initial) nonce for an object, advanced by version number.
Zeroth nonce can be used as object's id.
If you expect a particular id+version combination, you expect to use a particular nonce to open header.

There may be a scenario, in which two clients try to write same new version of an object.
In this concurrent case, they may send headers that use same nonce.
This opens a possibility for crypt-analysis of a header.
But since header only has info about segments structure and segment nonces, such crypt-analysis won't jeopardize the content.
When creating a new version, both clients will generate new random nonces for use in segments chains that constitute either whole, or a diff of a new version, ensuring that there is no segment nonce reuse.


### API for packing/opening XSP segments 

Let's import XSP-related functionality:
```javascript
import * as xsp from 'xsp-files';
```

There are two ways to make new version of an object.
First way is to encrypt new version of content from start to finish.
Second way is to encrypt only bytes for a new version, splicing them into untouched segments.
We call later approach as splicing writing, to distinguish it from the former, non-splicing writer.

Packing segments and header with a non-splicing writer:
```javascript
// non-slpicing writer for new file, or new, non-spliced (non-diff-ed) version
let writer = xsp.makeSegmentsWriter(
    key,    // this is object/file key
    zerothHeaderNonce,   // this is a zeroth nonce, used as id
    version,    // version that will be packed by the writer
    segSizein256bs, // full segment size, 16 gives 4*4*256B, or 4KB
    randomBytes,    // random numbers, used for segment nonces
    cryptor);   // is an async cryptor, used to encrypt segments and header

// header is produced by the following call
let header = await writer.packHeader();

// segments are packed with
let { seg, dataLen } = await writer.packSeg(content, segInd);
// where dataLen is a number of content bytes packed,
// and seg is an array with segment bytes.

// initial endless file can be set to be finite, this changes header information
writer.setContentLength(contentLen);

// writer should be destroyed, when no longer needed
writer.destroy();
```

Currently, at version 1.0.5, efficient splicing functionality is not 100% implemented, but it shall exist, as file format is designed for it.

Reader is used for reading:
```javascript
let reader = await xsp.makeSegmentsReader(
    key,    // this is object/file key
    zerothHeaderNonce,   // this is a zeroth nonce, used as id
    version,    // version that is expected to be read by this reader
    fileHeader, // object header, checked for version in this call
    cryptor);   // is an async cryptor, used to decrypt segments and header

let { data, segLen, last } = await reader.openSeg(seg, segInd);
// where segLen is a number of segment files read,
// where last is true for the last segment of this file,
// and data is an array with data, read from the segment.

// reader should be destroyed, when no longer needed
reader.destroy();
```


## License

This code is provided here under [Mozilla Public License Version 2.0](https://www.mozilla.org/MPL/2.0/).
