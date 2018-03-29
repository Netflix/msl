/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Payload chunk unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PayloadChunk", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var PayloadChunk = require('msl-core/msg/PayloadChunk.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslMessageException = require('msl-core/MslMessageException.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    var LzwCompression = require('msl-core/util/LzwCompression.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** RAW data file. */
    var DATAFILE = "pg1112.txt";

    /** Key payload. */
    var KEY_PAYLOAD = "payload";
    /** Key signature. */
    var KEY_SIGNATURE = "signature";

    // payload
    /** Key sequence number. */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key message ID. */
    var KEY_MESSAGE_ID = "messageid";
    /** Key end of message. */
    var KEY_END_OF_MESSAGE = "endofmsg";
    /** Key compression algorithm. */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** Key encrypted data. */
    var KEY_DATA = "data";

    // Shortcuts.
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;

    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Random. */
    var random = new Random();
    /** LZW instance. */
    var lzw = new LzwCompression();

    var CRYPTO_CONTEXT_ID = "cryptoContextId";

    var ENCRYPTION_KEY;
    var HMAC_KEY;

    var SEQ_NO = 1;
    var MSG_ID = 42;
    var END_OF_MSG = false;
    var DATA = TextEncoding.getBytes("We have to use some data that is compressible, otherwise payloads will not always use the compression we request.", TextEncoding.Encoding.UTF_8);
    var CRYPTO_CONTEXT;

    /** Raw data. */
    var rawdata;
    /** Large data. */
    var largedata = new Uint8Array(100 * 1024);
    random.nextBytes(largedata);

    /**
     * Uncompress the provided data using the specified compression algorithm.
     * 
     * @param {CompressionAlgorithm} compressionAlgo the compression algorithm.
     * @param {Uint8Array} data the data to uncompress.
     * @return {Uint8Array} the uncompressed data.
     * @throws MslException if there is an error uncompressing the data.
     */
    function uncompress(compressionAlgo, data) {
        switch (compressionAlgo) {
            case CompressionAlgorithm.LZW:
                return lzw.uncompress(data, MslConstants.MAX_LONG_VALUE);
            default:
                throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
        }
    }

    var initialized = false;
    beforeEach(function () {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);

            runs(function () {
                encoder = ctx.getMslEncoderFactory();

                var encryptionBytes = new Uint8Array(16);
                var hmacBytes = new Uint8Array(32);
                random.nextBytes(encryptionBytes);
                random.nextBytes(hmacBytes);

                SecretKey.import(encryptionBytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function (key) { ENCRYPTION_KEY = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(hmacBytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function (key) { HMAC_KEY = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return ENCRYPTION_KEY && HMAC_KEY; }, "ENCRYPTION_KEY and HMAC_KEY", MslTestConstants.TIMEOUT);

            runs(function() {
                CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, HMAC_KEY, null);

                initialized = true;
            });
        }
    });

    it("ctors", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
            expect(chunk.data).toEqual(DATA);
            expect(chunk.compressionAlgo).toBeNull();
            expect(chunk.messageId).toEqual(MSG_ID);
            expect(chunk.sequenceNumber).toEqual(SEQ_NO);

            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            expect(encode).not.toBeNull();
            PayloadChunk.parse(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.messageId).toEqual(chunk.messageId);
            expect(moChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
            moChunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            // The two payload chunk encodings will not be equal because the
            // ciphertext and signature will be generated on-demand.
        });
    });

    it("ctor with negative sequence number", function() {
        var exception;
        runs(function() {
            var sequenceNumber = -1;
            PayloadChunk.create(ctx, sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("ctor with too large sequence number", function() {
        var exception;
        runs(function() {
            var sequenceNumber = MslConstants.MAX_LONG_VALUE + 2;
            PayloadChunk.create(ctx, sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("ctor with negative message ID", function() {
        var exception;
        runs(function() {
            var messageId = -1;
            PayloadChunk.create(ctx, SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("ctor with too large message ID", function() {
        var exception;
        runs(function() {
            var messageId = MslConstants.MAX_LONG_VALUE + 2;
            PayloadChunk.create(ctx, SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("mslobject is correct", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var ciphertext, verified;
        runs(function() {
            expect(encode).not.toBeNull();
            var mo = encoder.parseObject(encode);
            ciphertext = mo.getBytes(KEY_PAYLOAD);
            var signature = mo.getBytes(KEY_SIGNATURE);
            CRYPTO_CONTEXT.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(verified).toBeTruthy();

            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            expect(payloadMo.getLong(KEY_SEQUENCE_NUMBER)).toEqual(SEQ_NO);
            expect(payloadMo.getLong(KEY_MESSAGE_ID)).toEqual(MSG_ID);
            expect(payloadMo.optBoolean(KEY_END_OF_MESSAGE)).toEqual(END_OF_MSG);
            expect(payloadMo.has(KEY_COMPRESSION_ALGORITHM)).toBeFalsy();
            expect(payloadMo.getBytes(KEY_DATA)).toEqual(DATA);
        });
    });

    xit("ctor with GZIP", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
            expect(chunk.data).toEqual(DATA);
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.GZIP);
            expect(chunk.messageId).toEqual(MSG_ID);
            expect(chunk.sequenceNumber).toEqual(SEQ_NO);
        });

        var encode;
        runs(function() {
            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            expect(encode).not.toBeNull();
            PayloadChunk.parse(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.messageId).toEqual(chunk.messageId);
            expect(moChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
            moChunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).toEqual(encode);
        });
    });

    xit("mslencode is correct with GZIP", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var verified, ciphertext;
        runs(function() {
            expect(encode).not.toBeNull();
            var mo = encoder.parseObject(encode);
            ciphertext = mo.getBytes(KEY_PAYLOAD);
            var signature = mo.getBytes(KEY_SIGNATURE);
            CRYPTO_CONTEXT.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(verified).toBeTruthy();

            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            expect(payloadMo.getLong(KEY_SEQUENCE_NUMBER)).toEqual(SEQ_NO);
            expect(payloadMo.getLong(KEY_MESSAGE_ID)).toEqual(MSG_ID);
            if (END_OF_MSG)
                expect(payloadMo.getBoolean(KEY_END_OF_MESSAGE)).toBeTruthy();
            else
                expect(payloadMo.getBoolean(KEY_END_OF_MESSAGE)).toBeFalsy();
            expect(payloadMo.getString(KEY_COMPRESSION_ALGORITHM)).toEqual(CompressionAlgorithm.GZIP);
            var gzipped = payloadMo.getBytes(KEY_DATA);
            uncompress(CompressionAlgorithm.GZIP, gzipped, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(plaintext).toEqual(DATA);
        });
    });

    it("ctor with LZW", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
            expect(chunk.data).toEqual(DATA);
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.LZW);
            expect(chunk.messageId).toEqual(MSG_ID);
            expect(chunk.sequenceNumber).toEqual(SEQ_NO);
        });

        var encode;
        runs(function() {
            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            expect(encode).not.toBeNull();
            PayloadChunk.parse(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
            expect(new Uint8Array(moChunk.data)).toEqual(chunk.data);
            expect(moChunk.messageId).toEqual(chunk.messageId);
            expect(moChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
            moChunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            // The two payload chunk encodings will not be equal because the
            // ciphertext and signature will be generated on-demand.
        });
    });

    it("json is correct with LZW", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            chunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var verified, ciphertext;
        runs(function() {
            expect(encode).not.toBeNull();
            var mo = encoder.parseObject(encode);
            ciphertext = mo.getBytes(KEY_PAYLOAD);
            var signature = mo.getBytes(KEY_SIGNATURE);
            CRYPTO_CONTEXT.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(verified).toBeTruthy();

            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            expect(payloadMo.getLong(KEY_SEQUENCE_NUMBER)).toEqual(SEQ_NO);
            expect(payloadMo.getLong(KEY_MESSAGE_ID)).toEqual(MSG_ID);
            expect(payloadMo.optBoolean(KEY_END_OF_MESSAGE)).toEqual(END_OF_MSG);
            expect(payloadMo.getString(KEY_COMPRESSION_ALGORITHM)).toEqual(CompressionAlgorithm.LZW);
            var lzw = payloadMo.getBytes(KEY_DATA);
            var plaintext = uncompress(CompressionAlgorithm.LZW, lzw);
            expect(new Uint8Array(plaintext)).toEqual(DATA);
        });
    });

    it("mismatched crypto context ID", function() {
        var cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "A", ENCRYPTION_KEY, HMAC_KEY, null);
        var cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "B", ENCRYPTION_KEY, HMAC_KEY, null);

        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, cryptoContextB, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.messageId).toEqual(chunk.messageId);
            expect(moChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
            moChunk.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            // The two payload chunk encodings will not be equal because the
            // ciphertext and signature will be generated on-demand.
        });
    });

    it("mismatched crypto context encryption key", function() {
        var encryptionKeyA, encryptionKeyB;
        runs(function() {
            var encryptionBytesA = new Uint8Array(16);
            var encryptionBytesB = new Uint8Array(16);
            random.nextBytes(encryptionBytesA);
            random.nextBytes(encryptionBytesB);
            SecretKey.import(encryptionBytesA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(x) { encryptionKeyA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            SecretKey.import(encryptionBytesB, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(x) { encryptionKeyB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encryptionKeyA && encryptionKeyB; }, "encryption keys", MslTestConstants.TIMEOUT);

        // Mismatched encryption keys will just result in the wrong data.
        var cryptoContextA, cryptoContextB;
        var chunk;
        runs(function() {
            cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyA, HMAC_KEY, null);
            cryptoContextB = new SymmetricCryptoContext(ctx,CRYPTO_CONTEXT_ID, encryptionKeyB, HMAC_KEY, null);

            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return cryptoContextA && cryptoContextB && chunk; }, "crypto contexts and chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            PayloadChunk.parse(ctx, mo, cryptoContextB, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            // Sometimes decryption will succeed so check for a crypto exception
            // or encoding exception. Both are OK.
            expect(exception instanceof MslCryptoException || exception instanceof MslEncodingException);
        });
    });

    it("mismatched crypto context signing key", function() {
        var hmacKeyA, hmacKeyB;
        runs(function() {
            var hmacBytesA = new Uint8Array(32);
            var hmacBytesB = new Uint8Array(32);
            random.nextBytes(hmacBytesA);
            random.nextBytes(hmacBytesB);
            SecretKey.import(hmacBytesA, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                result: function(x) { hmacKeyA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            SecretKey.import(hmacBytesB, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                result: function(x) { hmacKeyB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return hmacKeyA && hmacKeyB; }, "HMAC keys", MslTestConstants.TIMEOUT);

        var cryptoContextA, cryptoContextB;
        var chunk;
        runs(function() {
            cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyA, null);
            cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyB, null);

            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return cryptoContextA && cryptoContextB && chunk; }, "crypto contexts and chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            PayloadChunk.parse(ctx, mo, cryptoContextB, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED));
        });
    });

    it("incorrect signature", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var signature = new Uint8Array(32);
            random.nextBytes(signature);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED));
        });
    });

    it("missing payload", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.remove(KEY_PAYLOAD);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid payload", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, "x");

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("corrupt payload", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            var ciphertext = new Uint8Array(32);
            random.nextBytes(ciphertext);
            mo.put(KEY_PAYLOAD, ciphertext);
            CRYPTO_CONTEXT.sign(ciphertext, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });

    it("empty end of message payload", function() {
        var chunk;
        runs(function() {
            var data = new Uint8Array(0);
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, data, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moChunk.data.length).toEqual(0);
        });
    });

    it("missing sequence number", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);

            payloadMo.remove(KEY_SEQUENCE_NUMBER);

            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid sequence number", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_SEQUENCE_NUMBER, "x");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("negative sequence number", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_SEQUENCE_NUMBER, -1);
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });

    it("too large sequence number", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });

    it("missing message ID", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.remove(KEY_MESSAGE_ID);
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid message ID", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_MESSAGE_ID, "x");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid end of message", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_END_OF_MESSAGE, "x");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid compression algorithm", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_COMPRESSION_ALGORITHM, "x");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION));
        });
    });

    it("missing data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.remove(KEY_DATA);
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("empty data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_DATA, "");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.PAYLOAD_DATA_MISSING));
        });
    });

    it("end of message payload with invalid data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            var ciphertext = mo.getBytes(KEY_PAYLOAD);
            CRYPTO_CONTEXT.decrypt(ciphertext, encoder, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            var payloadMo = encoder.parseObject(payload);
            payloadMo.put(KEY_DATA, "x");
            encoder.encodeObject(payloadMo, ENCODER_FORMAT, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var newPayload;
        runs(function() {
            CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(data) { newPayload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return newPayload; }, "newPayload", MslTestConstants.TIMEOUT);

        var signature;
        runs(function() {
            CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT, {
                result: function(data) { signature = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_PAYLOAD, newPayload);
            mo.put(KEY_SIGNATURE, signature);

            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    // large data requires a longer timeout
    it("large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", 3000);

        var mo;
        runs(function() {
            expect(chunk.data).toEqual(largedata);
            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", 3000);

        runs(function() {
            expect(moChunk.data).toEqual(chunk.data);
        });
    });

    // large data requires a longer timeout
    xit("GZIP large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", 3000);

        var mo;
        runs(function() {
            expect(chunk.data).toEqual(largedata);

            // Random data will not compress.
            expect(chunk.compressionAlgo).toBeNull();

            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", 3000);

        runs(function() {
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });

    xit("GZIP verona", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, rawdata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            expect(chunk.data).toEqual(rawdata);

            // Romeo and Juliet will compress.
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.GZIP);

            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });

    // large data requires a longer timeout
    it("LZW large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", 3000);

        var mo;
        runs(function() {
            expect(chunk.data).toEqual(largedata);

            // Random data will not compress.
            expect(chunk.compressionAlgo).toBeNull();

            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", 3000);
        runs(function() {
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });

    xit("LZW verona", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, rawdata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            expect(chunk.data).toEqual(rawdata);

            // Romeo and Juliet will compress.
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.LZW);

            MslTestUtils.toMslObject(encoder, chunk, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moChunk;
        runs(function() {
            PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                result: function(x) { moChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moChunk; }, "moChunk", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moChunk.data).toEqual(chunk.data);
            expect(moChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });

    xit("equals sequence number", function() {
        var seqNoA = 1;
        var seqNoB = 2;
        var chunkA, chunkB;
        runs(function() {
            PayloadChunk.create(ctx, seqNoA, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, seqNoB, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks", MslTestConstants.TIMEOUT);
        var chunkA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunkA, {
                result: function(mo) {
                    PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                        result: function(x) { chunkA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunkA.equals(chunkA)).toBeTruthy();
            expect(chunkA.uniqueKey()).toEqual(chunkA.uniqueKey());

            expect(chunkA.equals(chunkB)).toBeFalsy();
            expect(chunkB.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkB.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkA2)).toBeTruthy();
            expect(chunkA2.equals(chunkA)).toBeTruthy();
            expect(chunkA2.uniqueKey()).toEqual(chunkA.uniqueKey());
        });
    });

    xit("equals message ID", function() {
        var msgIdA = 1;
        var msgIdB = 2;
        var chunkA, chunkB;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, msgIdA, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, SEQ_NO, msgIdB, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks", MslTestConstants.TIMEOUT);
        var chunkA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunkA, {
                result: function(mo) {
                    PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                        result: function(x) { chunkA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunkA.equals(chunkA)).toBeTruthy();
            expect(chunkA.uniqueKey()).toEqual(chunkA.uniqueKey());

            expect(chunkA.equals(chunkB)).toBeFalsy();
            expect(chunkB.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkB.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkA2)).toBeTruthy();
            expect(chunkA2.equals(chunkA)).toBeTruthy();
            expect(chunkA2.uniqueKey()).toEqual(chunkA.uniqueKey());
        });
    });

    xit("equals end of message", function() {
        var chunkA, chunkB;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks", MslTestConstants.TIMEOUT);
        var chunkA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunkA, {
                result: function(mo) {
                    PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                        result: function(x) { chunkA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunkA.equals(chunkA)).toBeTruthy();
            expect(chunkA.uniqueKey()).toEqual(chunkA.uniqueKey());

            expect(chunkA.equals(chunkB)).toBeFalsy();
            expect(chunkB.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkB.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkA2)).toBeTruthy();
            expect(chunkA2.equals(chunkA)).toBeTruthy();
            expect(chunkA2.uniqueKey()).toEqual(chunkA.uniqueKey());
        });
    });

    xit("equals compression algorithm", function() {
        var chunkA, chunkB;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks", MslTestConstants.TIMEOUT);
        var chunkA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunkA, {
                result: function(mo) {
                    PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                        result: function(x) { chunkA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunkA.equals(chunkA)).toBeTruthy();
            expect(chunkA.uniqueKey()).toEqual(chunkA.uniqueKey());

            expect(chunkA.equals(chunkB)).toBeFalsy();
            expect(chunkB.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkB.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkA2)).toBeTruthy();
            expect(chunkA2.equals(chunkA)).toBeTruthy();
            expect(chunkA2.uniqueKey()).toEqual(chunkA.uniqueKey());
        });
    });

    xit("equals data", function() {
        var dataA = new Uint8Array(32);
        random.nextBytes(dataA);
        var dataB = new Uint8Array(32);
        random.nextBytes(dataB);
        var dataC = new Uint8Array(0);
        var chunkA, chunkB, chunkC;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, dataA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, dataB, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, dataC, CRYPTO_CONTEXT, {
                result: function(x) { chunkC = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB && chunkC; }, "chunks", MslTestConstants.TIMEOUT);
        var chunkA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, chunkA, {
                result: function(mo) {
                    PayloadChunk.parse(ctx, mo, CRYPTO_CONTEXT, {
                        result: function(x) { chunkA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunkA.equals(chunkA)).toBeTruthy();
            expect(chunkA.uniqueKey()).toEqual(chunkA.uniqueKey());

            expect(chunkA.equals(chunkB)).toBeFalsy();
            expect(chunkB.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkB.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkC)).toBeFalsy();
            expect(chunkC.equals(chunkA)).toBeFalsy();
            expect(chunkA.uniqueKey() != chunkC.uniqueKey()).toBeTruthy();

            expect(chunkA.equals(chunkA2)).toBeTruthy();
            expect(chunkA2.equals(chunkA)).toBeTruthy();
            expect(chunkA2.uniqueKey()).toEqual(chunkA.uniqueKey());
        });
    });

    xit("equals object", function() {
        var chunk;
        runs(function() {
            PayloadChunk.create(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(chunk.equals(null)).toBeFalsy();
            expect(chunk.equals(CRYPTO_CONTEXT_ID)).toBeFalsy();
            expect(chunk.uniqueKey() != CRYPTO_CONTEXT_ID.uniqueKey()).toBeTruthy();
        });
    });
});
