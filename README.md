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

Building is done with [gulp](http://gulpjs.com/), version 4, exposed via npm script.
Do in the folder

    npm run gulp help

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
 * file should be encrypted by its own key, encrypted with some external (master) key;
 * there should be a stream-like setting, where segments can be encrypted and read without knowledge of a final length;
 * when complete length of a stream is finally known, switching to known-length setting should be cheap.

We call this format XSP, to stand for XSalsa+Poly, to indicate that file layout
is specifically tailored for storing NaCl's secret box's ciphers.
XSP file has segments, which are NaCl's packs of Poly and XSalsa cipher, and a header.
Header is stored at the end of the file, when segments and header are stored in a single file object.
Sometimes, XSP segments and a header can be stored in separate files.

Complete XSP file looks as following (starting with UTF-8 'xsp'):

    +-----+ +---------------+ +----------+ +--------+
    | xsp | | header offset | | segments | | header |
    +-----+ +---------------+ +----------+ +--------+

When file parts are stored separately, header file starts with UTF-8 'hxsp', and segments' file starts with UTF-8 'sxsp'.

Header can be of two types, distinguished by header's size.

### Endless file

(72+65)-byte header is used for a file with unknown length (endless file), and looks as follows:

    |<-  72 bytes ->| |<-          65 bytes          ->|
    +---------------+ +--------------------------------+
    |   file key    | | seg size | first segment nonce |
    +---------------+ +--------------------------------+
    |<- WN format ->| |<-          WN format         ->|

 * WN pack of a file key is encrypted with master key. Everything else is encrypted with the file key.
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

(72+46+n*30)-byte header is used for a file with known length (finite file).
n is a number of segment chains in the file.
Header layout:

    |<-  72 bytes ->| |<-              46+n*30 bytes                ->|
    +---------------+ +-----------------------------------------------+
    |   file key    | | total segs length | | seg size | | seg chains |
    +---------------+ +-----------------------------------------------+
    |<- WN format ->| |<-                WN format                  ->|

 * Total segments length, is just that. It excludes header and other file elements.
 * Total segments length is encoded big-endian way into 5 bytes, allowing up to 2^40-1 bytes, or 1TB - 1byte.
 * Content length is equal to total segments length minus 16*n, where n is a total number of segments (16 bytes is poly's code length).

Segment chain bytes look as following:

    |<-   4 bytes  ->| |<-  2 bytes  ->| |<-     24 bytes    ->|
    +----------------+ +---------------+ +---------------------+
    | number of segs | | last seg size | | first segment nonce |
    +----------------+ +---------------+ +---------------------+


### API for packing/opening XSP segments 

There is a sub-module, with XSP-related functionality:
```javascript
import * as xsp from 'xsp-files';
```

Start work with any file by creating an object that holds file key, and, therefore, can generate correct readers and writers.
```javascript
// for a new file, the following generates new file key, contained in the holder
let fkeyHolder = xsp.makeNewFileKeyHolder(mkeyEncr, getRandom);

// existing file has its key packed in its header, which should be used
let fkeyHolder = xsp.makeFileKeyHolder(mkeyDecr, header);
```

Packing segments and header:  
```javascript
// new file writer needs segment size and a function to get random bytes
let writer = fkeyHolder.newSegWriter(segSizein256bs, getRandom);

// header is produced by the following call
let header = writer.packHeader();

// segments are packed with
let sInfo = writer.packSeg(content, segInd);
// where sInfo.dataLen is a number of content bytes packed,
// and sInfo.seg is an array with segment bytes.

// initial endless file can be set to be finite, this changes header information
writer.setContentLength(contentLen);

// writer of existing file should read existing header
let writer = xsp.segments.makeWriter(header, getRandom);

// writer should be destroyed, when no longer needed
writer.destroy();
```

Currently, at version 2.2.0, efficient splicing functionality is not implemented, but it shall exist, as file format allows for it.
We also plan to add some fool-proof restrictions into implementation to disallow packing the same segment twice.
For now, users are advised to be careful, and to pack each segment only once.

Reader is used for reading:
```javascript
let reader = xsp.segments.makeReader(header, masterKeyDecr);

let dInfo = reader.openSeg(seg, segInd);
// where dInfo.segLen is a number of segment files read,
// where dInfo.last is true for the last segment of this file,
// and dInfo.data is an array with data, read from the segment.

// reader should be destroyed, when no longer needed
reader.destroy();
```


## License

This code is provided here under [Mozilla Public License Version 2.0](https://www.mozilla.org/MPL/2.0/).
