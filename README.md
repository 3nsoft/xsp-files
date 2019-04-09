# XSP format for NaCl-encrypted files (XSalsa+Poly).

XSP file format for objects encrypted with NaCl. 

## Get xsp-files

### NPM Package

This library is registered on
[npmjs.org](https://npmjs.org/package/xsp-files). To install it, do:

    npm install xsp-files

Package comes with already compiled library code in dist/ folder. For testing, bring up a build environment and run npm test script(s).

### Building

Once you get package, or this repo, do in the folder

    npm ci

which will install dev-dependencies. Note that option `ci` brings exact versions, mentioned in `package-lock.json`, while option `i` (`install`) may get other versions, based on ranges in `package.json`.

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
XSP file has header, and zero or many segments with data.

Segments are NaCl's packs of Poly and XSalsa cipher.
```
    +------+ +---------------+
    | poly | |  data cipher  |
    +------+ +---------------+
    | <--  NaCl format   --> |
```
Header is packed with its nonce into WN format (introduced in ecma-nacl):
```
    +-------+ +------+ +---------------+
    | nonce | | poly | |  data cipher  |
    +-------+ +------+ +---------------+
    | <----       WN format      ----> |
```


### Header data

Header provides information about segments, their nonces, and expected sizes. It contains the following:
```
    |<- 1 byte ->| |<-   2  ->| |<-  n*31  ->|
    +------------+ +----------+ +------------+
    |   version  | | seg size | | seg chains |
    +------------+ +----------+ +------------+
```
* Version byte is a positive integer. Current version is 1.
* Two big-endian bytes have a non-negative integer with segment content size in 256 byte units. Packed segment size is this plus 16 bytes (for Poly). Last segments in segment chains can be shorter.
* Info about `n=0,1,...` segment chains.

Data segments come in chains. Segments in the same chain have consecutive nonces. All segments should be the same size, except for the last segment in a chain.

Segment chain is described in header with following bytes:
```
    |<-   4 bytes  ->| |<-  3 bytes  ->| |<-     24 bytes    ->|
    +----------------+ +---------------+ +---------------------+
    | number of segs | | last seg size | | first segment nonce |
    +----------------+ +---------------+ +---------------------+
    |<-                    seg chain                         ->|
```
* First 4 bytes is a big-endian encoded non-negative integer number of segments in this chain.
* Following 3 bytes is a big-endian encoded non-negative integer with the last segment content length in this chain.
* Last 24 bytes is a nonce of the first segment in this chain. Nonces for all other segments are calculated by advancing this nonce. For example, advancing this nonce by one, we get nonce for the second segment in the chain, and so on. Nonce advancing function comes from ecma-nacl, treating 24-byte nonce as three 64-bit unsigned integers to which respective number is added.

In a situation when writer has to send file's header before knowing total file length, the last chain can be infinite. Number of segments in infinite chain is set to be `0xffffffff`, which is used as the maximum possible segment index. Last segment size in infinite chain is set to common segment size.

Let's note that since nonce for every chain is unique, it is possible to calculated differences between two versions, i.e. what segments of file have changed, and which stayed the same. Segments that stay same guarantee that respective section of file's content stay the same.


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


### API for XSP segments 

Let's import XSP-related functionality:
```javascript
import * as xsp from 'xsp-files';
```

#### Opening segments

Reader is used for reading.
```javascript
let reader = await xsp.makeSegmentsReader(
    key,    // this is object/file key
    zerothHeaderNonce,   // this is a zeroth nonce, used as id
    version,    // version that is expected to be read by this reader
    fileHeader, // object header, checked for version in this call
    cryptor);   // is an async cryptor, used to decrypt segments and header
```
Reader provides a few informational functions, and a segment opening function. Reading XSP file starting from the very first segment may look as follows
```javascript
// content length may be set, or, if it was unknown at time of header creation,
// content length will be undefined
const contentLength = reader.contentLength;

// This is an iterator from the first segment. To start from another segment, give an index
let segInfosIter = reader.segmentInfos();

// assume that this contains all encrypted segments
const allEncrBytes = ... // Uint8Array type

for (const segInfo of segInfosIter) {
    // get encrypted bytes of a particular segment using segInfo
    const encrBytes = allEncrBytes.subarray(
        segInfo.packedOfs, segInfo.packedOfs + segInfo.packedLen);

    // decrypt segment's content bytes
    const content = await reader.openSeg(segInfo, encrBytes);

    // do something with decrypted content of a segment ...
}

// reader should be destroyed, when no longer needed
reader.destroy();
```

#### Packing segments

Writer is used for encrypting (packing) segments. For writing all new segments from start to finish, we use option `new`:
```javascript
let writer = await makeSegmentsWriter(
    key,    // this is object/file key
    zerothHeaderNonce,   // this is a zeroth nonce, used as id
    version,    // version that will be packed by the writer
    { type: 'new', segSize: segSizein256bs },   // option to create writer for
    // all new segments with full size in 256bytes, e.g. 16 equals 4*4*256B, or 4KB size
    randomBytes,    // random numbers, used for segment nonces
    cryptor);   // is an async cryptor, used to encrypt segments and header
```
For writing an updated version, given an object source of a base version, `baseSrc`, we use option `update` to write only partial update of a file:
```javascript
let writer = await makeSegmentsWriter(
    key, zerothHeaderNonce, version,
    { type: 'update', base: baseSrc },   // option to create writer for updated
    // segments. baseSrc is used to reencrypt those base bytes located on
    // boundaries of base and updated segments
    randomBytes, cryptor);
```

We may use writer's information and packing functions directly, or we may use a sink with simpler api for streaming:
```javascript
const { sink, sub } = await xsp.makeEncryptingByteSink(writer);

// we can put content into sink at a given offset, result shows in the events
await sink.write(ofs, content);

// sub is an event subscribing function that fits well with rxjs,
// and with an optional backpressure function can have
const enc$ = Observable.create(obs => sub(obs, backpressure)).share();

// there is a couple of encryption events:
// - event with encrypted header and layout information
const headerEvent$ = enc$.filter(ev => (ev.type === 'header'));
// - events with encrypted segment chunks
const segEvent$ = enc$.filter(ev => (ev.type === 'seg'));

// header event sets xsp object's geometry/layout, it can't change afterwards
headerEvent$
.flatMap(async headerEvent => {
    // layout information can be used to adjust saving/sending strategy
    foo( headerEvent.layout );
    // header bytes here can be sent/saved, etc.
    bar( headerEvent.header );
});

// segment events contain packed segments, and some info about location
segEvent$
.flatMap(async segEvent => {
    fooBar(
        segEvent.segInfo,   // information about segment
        segEvent.seg);    // segment bytes
});
```

#### Cleanup

As with reader, writer should be destroyed after use:
```javascript
writer.destroy();
```



## License

This code is provided here under [GNU Public License Version 3](https://www.mozilla.org/MPL/2.0/).

XSP object format is free for anyone to use, to implement, to do anything with them.
