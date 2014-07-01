/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
    /** RAW data file. */
    var DATAFILE = "pg1112.txt";
    
    /** JSON key payload. */
    var KEY_PAYLOAD = "payload";
    /** JSON key signature. */
    var KEY_SIGNATURE = "signature";
    
    // payload
    /** JSON key sequence number. */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** JSON key message ID. */
    var KEY_MESSAGE_ID = "messageid";
    /** JSON key end of message. */
    var KEY_END_OF_MESSAGE = "endofmsg";
    /** JSON key compression algorithm. */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** JSON key encrypted data. */
    var KEY_DATA = "data";
    
    // Shortcuts.
    var CompressionAlgorithm = MslConstants$CompressionAlgorithm;
    
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
    		return lzw$uncompress(data);
    	default:
    		throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
    	}
    }
    
    /** MSL context. */
    var ctx;
    /** Random. */
    var random = new Random();
    
    var CRYPTO_CONTEXT_ID = "cryptoContextId";

    var ENCRYPTION_KEY;
    var HMAC_KEY;
    
    var SEQ_NO = 1;
    var MSG_ID = 42;
    var END_OF_MSG = false;
    var DATA = textEncoding$getBytes("We have to use some data that is compressible, otherwise payloads will not always use the compression we request.", MslConstants$DEFAULT_CHARSET);
    var CRYPTO_CONTEXT;

    /** Raw data. */
    var rawdata;
    /** Large data. */
    var largedata = new Uint8Array(100 * 1024);
    random.nextBytes(largedata);

    var initialized = false;
    beforeEach(function () {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);

            runs(function () {
                var encryptionBytes = new Uint8Array(16);
                var hmacBytes = new Uint8Array(32);
                random.nextBytes(encryptionBytes);
                random.nextBytes(hmacBytes);
                
                CipherKey$import(encryptionBytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function (key) { ENCRYPTION_KEY = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
                CipherKey$import(hmacBytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function (key) { HMAC_KEY = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return ENCRYPTION_KEY && HMAC_KEY; }, "ENCRYPTION_KEY and HMAC_KEY", 100);
            
            runs(function() {
                CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, HMAC_KEY, null);
                
                initialized = true;
            });
        }
    });

    it("ctors", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        runs(function() {
	        expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
	        expect(chunk.data).toEqual(DATA);
	        expect(chunk.compressionAlgo).toBeNull();
	        expect(chunk.messageId).toEqual(MSG_ID);
	        expect(chunk.sequenceNumber).toEqual(SEQ_NO);
        });

        var jsonString = undefined, joChunk;
        runs(function() {
	        jsonString = JSON.stringify(chunk);
	        expect(jsonString).not.toBeNull();
            PayloadChunk$parse(JSON.parse(jsonString), CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joChunk; }, "json string and joChunk not received", 100);
        
        runs(function() {
	        waitsFor(function() { return joChunk; }, "joChunk not received", 100);
	        expect(joChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
	        expect(joChunk.data).toEqual(chunk.data);
	        expect(joChunk.messageId).toEqual(chunk.messageId);
	        expect(joChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
	        var joJsonString = JSON.stringify(joChunk);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("ctor with negative sequence number", function() {
    	var exception;
    	runs(function() {
            var sequenceNumber = -1;
	        PayloadChunk$create(sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });
    
    it("ctor with too large sequence number", function() {
    	var exception;
    	runs(function() {
	        var sequenceNumber = MslConstants$MAX_LONG_VALUE + 2;
	        PayloadChunk$create(sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });
    
    it("ctor with negative message ID", function() {
    	var exception;
    	runs(function() {
    		var messageId = -1;
	        PayloadChunk$create(SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });
    
    it("ctor with too large message ID", function() {
    	var exception;
    	runs(function() {
	        var messageId = MslConstants$MAX_LONG_VALUE + 2;
	        PayloadChunk$create(SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });
    
    it("json is correct", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var ciphertext = undefined, verified;
        runs(function() {
	        var jsonString = JSON.stringify(chunk);
	        expect(jsonString).not.toBeNull();
	        var jo = JSON.parse(jsonString);
	        ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        CRYPTO_CONTEXT.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified not received", 100);
        runs(function() {
	        expect(verified).toBeTruthy();
        });
        
        var payload;
        runs(function() {
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload not received", 100);
        runs(function() {
	        var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        expect(parseInt(payloadJo[KEY_SEQUENCE_NUMBER])).toEqual(SEQ_NO);
	        expect(parseInt(payloadJo[KEY_MESSAGE_ID])).toEqual(MSG_ID);
	        expect(payloadJo[KEY_END_OF_MESSAGE] || false).toEqual(END_OF_MSG);
	        expect(payloadJo[KEY_COMPRESSION_ALGORITHM]).toBeFalsy();
	        expect(base64$decode(payloadJo[KEY_DATA])).toEqual(DATA);
        });
    });
    
    xit("ctor with GZIP", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        runs(function() {
	        expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
	        expect(chunk.data).toEqual(DATA);
	        expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.GZIP);
	        expect(chunk.messageId).toEqual(MSG_ID);
	        expect(chunk.sequenceNumber).toEqual(SEQ_NO);
        });

        var jsonString = undefined, joChunk;
        runs(function() {
            jsonString = JSON.stringify(chunk);
            expect(jsonString).not.toBeNull();
            PayloadChunk$parse(JSON.parse(jsonString), CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joChunk; }, "json string and joChunk not received", 100);
        runs(function() {
	        expect(joChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
	        expect(joChunk.data).toEqual(chunk.data);
	        expect(joChunk.messageId).toEqual(chunk.messageId);
	        expect(joChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
	        var joJsonString = JSON.stringify(joChunk);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    xit("json is correct with GZIP", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var verified = undefined, ciphertext;
        runs(function() {
	        var jsonString = JSON.stringify(chunk);
	        expect(jsonString).not.toBeNull();
	        var jo = JSON.parse(jsonString);
	        ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        CRYPTO_CONTEXT.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified not received", 100);
        runs(function() {
        	expect(verified).toBeTruthy();
        });
        
        var payload;
        runs(function() {
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload not received", 100);
        
        var plaintext;
        runs(function() {
	        var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        expect(parseInt(payloadJo[KEY_SEQUENCE_NUMBER])).toEqual(SEQ_NO);
	        expect(parseInt(payloadJo[KEY_MESSAGE_ID])).toEqual(MSG_ID);
	        if (END_OF_MSG)
	        	expect(payloadJo[KEY_END_OF_MESSAGE]).toBeTruthy();
	        else
	        	expect(payloadJo[KEY_END_OF_MESSAGE]).toBeFalsy();
	        expect(payloadJo[KEY_COMPRESSION_ALGORITHM]).toEqual(CompressionAlgorithm.GZIP.toString());
	        var gzipped = base64$decode(payloadJo[KEY_DATA]);
	        uncompress(CompressionAlgorithm.GZIP, gzipped, {
	        	result: function(x) { plaintext = x; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return plaintext; }, "plaintext not received", 100);
        
        runs(function() {
	        expect(plaintext).toEqual(DATA);
        });
    });
    
    it("ctor with LZW", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        runs(function() {
	        expect(chunk.isEndOfMessage()).toEqual(END_OF_MSG);
	        expect(chunk.data).toEqual(DATA);
	        expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.LZW);
	        expect(chunk.messageId).toEqual(MSG_ID);
	        expect(chunk.sequenceNumber).toEqual(SEQ_NO);
        });

        var jsonString = undefined, joChunk;
        runs(function() {
            jsonString = JSON.stringify(chunk);
            expect(jsonString).not.toBeNull();
            PayloadChunk$parse(JSON.parse(jsonString), CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joChunk; }, "json string and joChunk not received", 100);
        runs(function() {
	        expect(joChunk.isEndOfMessage()).toEqual(chunk.isEndOfMessage());
	        expect(new Uint8Array(joChunk.data)).toEqual(chunk.data);
	        expect(joChunk.messageId).toEqual(chunk.messageId);
	        expect(joChunk.sequenceNumber).toEqual(chunk.sequenceNumber);
	        var joJsonString = JSON.stringify(joChunk);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("json is correct with LZW", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var verified = undefined, ciphertext;
        runs(function() {
	        var jsonString = JSON.stringify(chunk);
	        expect(jsonString).not.toBeNull();
	        var jo = JSON.parse(jsonString);
	        ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        CRYPTO_CONTEXT.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return ciphertext && verified !== undefined; }, "ciphertext and verified not received", 100);
        runs(function() {
        	expect(verified).toBeTruthy();
        });
        
        var payload;
        runs(function() {
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload not received", 100);
        
        runs(function() {
	        var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        expect(parseInt(payloadJo[KEY_SEQUENCE_NUMBER])).toEqual(SEQ_NO);
	        expect(parseInt(payloadJo[KEY_MESSAGE_ID])).toEqual(MSG_ID);
	        if (END_OF_MSG)
	        	expect(payloadJo[KEY_END_OF_MESSAGE]).toBeTruthy();
	        else
	        	expect(payloadJo[KEY_END_OF_MESSAGE]).toBeFalsy();
	        expect(payloadJo[KEY_COMPRESSION_ALGORITHM]).toEqual(CompressionAlgorithm.LZW.toString());
	        var lzw = base64$decode(payloadJo[KEY_DATA]);
	        var plaintext = uncompress(CompressionAlgorithm.LZW, lzw);
	        expect(new Uint8Array(plaintext)).toEqual(DATA);
        });
    });
    
    it("mismatched crypto context ID", function() {
    	var cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "A", ENCRYPTION_KEY, HMAC_KEY, null);
    	var cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "B", ENCRYPTION_KEY, HMAC_KEY, null);

    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	        PayloadChunk$parse(jo, cryptoContextB, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });
    
    it("mismatched crypto context encryption key", function() {
        var encryptionKeyA = undefined, encryptionKeyB;
        runs(function() {
            var encryptionBytesA = new Uint8Array(16);
            var encryptionBytesB = new Uint8Array(16);
            random.nextBytes(encryptionBytesA);
            random.nextBytes(encryptionBytesB);
            CipherKey$import(encryptionBytesA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(x) { encryptionKeyA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            CipherKey$import(encryptionBytesB, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(x) { encryptionKeyB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encryptionKeyA && encryptionKeyB; }, "encryption keys", 100);

    	// Mismatched encryption keys will just result in the wrong data.
    	var cryptoContextA = undefined, cryptoContextB;
    	var chunk;
        runs(function() {
            cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyA, HMAC_KEY, null);
            cryptoContextB = new SymmetricCryptoContext(ctx,CRYPTO_CONTEXT_ID, encryptionKeyB, HMAC_KEY, null);
            
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return cryptoContextA && cryptoContextB && chunk; }, "crypto contexts and chunk not received", 100);
        
        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	        PayloadChunk$parse(jo, cryptoContextB, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	// Sometimes decryption will succeed so check for a crypto exception
        	// or encoding exception. Both are OK.
        	expect(exception instanceof MslCryptoException || exception instanceof MslEncodingException);
        });
    });
    
    it("mismatched crypto context signing key", function() {
        var hmacKeyA = undefined, hmacKeyB;
        runs(function() {
        	var hmacBytesA = new Uint8Array(32);
        	var hmacBytesB = new Uint8Array(32);
        	random.nextBytes(hmacBytesA);
        	random.nextBytes(hmacBytesB);
        	CipherKey$import(hmacBytesA, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        	    result: function(x) { hmacKeyA = x; },
        	    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	CipherKey$import(hmacBytesB, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        	    result: function(x) { hmacKeyB = x; },
        	    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return hmacKeyA && hmacKeyB; }, "HMAC keys", 100);

    	var cryptoContextA = undefined, cryptoContextB;
    	var chunk;
    	runs(function() {
            cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyA, null);
            cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyB, null);
            
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContextA, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return cryptoContextA && cryptoContextB && chunk; }, "crypto contexts and chunk not received", 100);
        
        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	        PayloadChunk$parse(jo, cryptoContextB, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
	    });
	    waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED));
        });
    });
    
    it("incorrect signature", function() {
    	var chunk;
    	runs(function() {
    		PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
    			result: function(x) { chunk = x; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	        
	        var signature = new Uint8Array(32);
	        random.nextBytes(signature);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED));
        });
    });
    
    it("missing payload", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	        
	        expect(jo[KEY_PAYLOAD]).not.toBeNull();
	        delete jo[KEY_PAYLOAD];
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid payload", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var exception;
        runs(function() {
	        var jo = JSON.parse(JSON.stringify(chunk));
	
	        jo[KEY_PAYLOAD] = "AAA=";
	
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED));
        });
    });
    
    it("corrupt payload", function() {
	        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, signature;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	
	        var ciphertext = new Uint8Array(32);
	        random.nextBytes(ciphertext);
	        jo[KEY_PAYLOAD] = base64$encode(ciphertext);
	        CRYPTO_CONTEXT.sign(ciphertext, {
	        	result: function(data) { signature = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return jo && signature; }, "json object and signature not received", 100);

	   var exception;
	   runs(function() {
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });
    
    it("empty end of message payload", function() {
        var chunk;
        runs(function() {
        	var data = new Uint8Array(0);
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, data, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var joChunk;
        runs(function() {
        	var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 100);
        runs(function() {
        	expect(joChunk.data.length).toEqual(0);
        });
    });
    
    it("missing sequence number", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var jo = undefined, payload;
	    runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        CRYPTO_CONTEXT.decrypt(ciphertext, {
	        	result: function(data) { payload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	    });
	    waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
	    
	    var newPayload;
        runs(function() {
            var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        
	        expect(payloadJo[KEY_SEQUENCE_NUMBER]).not.toBeNull();
	        delete payloadJo[KEY_SEQUENCE_NUMBER];
	
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
        
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid sequence number", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var jo = undefined, payload;
        runs(function() {
        	jo = JSON.parse(JSON.stringify(chunk));
        	var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
        	CRYPTO_CONTEXT.decrypt(ciphertext, {
        		result: function(data) { payload = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);

        var newPayload;
        runs(function() {
	        var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_SEQUENCE_NUMBER] = "x";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);

        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("negative sequence number", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var jo = undefined, payload;
        runs(function() {
        	jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        CRYPTO_CONTEXT.decrypt(ciphertext, {
	        	result: function(data) { payload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);

        var newPayload;
        runs(function() {
        	var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_SEQUENCE_NUMBER] = -1;
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
	    
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);

        var exception;
        runs(function() {
	        jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("too large sequence number", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
        	jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
	        CRYPTO_CONTEXT.decrypt(ciphertext, {
	        	result: function(data) { payload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);

        var newPayload;
        runs(function() {
        	var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_SEQUENCE_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
	    
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);

        var exception;
        runs(function() {
	        jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("missing message ID", function() {
	    var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);

        var newPayload;
        runs(function() {
        	var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        expect(payloadJo[KEY_MESSAGE_ID]).not.toBeNull();
	        delete payloadJo[KEY_MESSAGE_ID];
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
        
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
	        jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);

	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid message ID", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);

        var newPayload;
        runs(function() {
            var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_MESSAGE_ID] = "x";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);

        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
        	jo[KEY_SIGNATURE] = base64$encode(signature);

        	PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
        		result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid end of message", function() {
	        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
        
        var newPayload;
        runs(function() {
        	var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_END_OF_MESSAGE] = "x";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);

        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
     
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
        	jo[KEY_SIGNATURE] = base64$encode(signature);

        	PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid compression algorithm", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
        
        var newPayload;
        runs(function() {
        	var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_COMPRESSION_ALGORITHM] = "x";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
 
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION));
        });
    });
    
    it("missing data", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
        
        var newPayload;
        runs(function() {
            var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        expect(payloadJo[KEY_DATA]).not.toBeNull();
	        delete payloadJo[KEY_DATA];
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
 
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
     
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("empty data", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
        
        var newPayload;
        runs(function() {
            var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_DATA] = "";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);
 
        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
	        jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.PAYLOAD_DATA_MISSING));
        });
    });

    it("end of message payload with invalid data", function() {
    	var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);

        var jo = undefined, payload;
        runs(function() {
	        jo = JSON.parse(JSON.stringify(chunk));
	        var ciphertext = base64$decode(jo[KEY_PAYLOAD]);
            CRYPTO_CONTEXT.decrypt(ciphertext, {
                result: function(data) { payload = data; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jo && payload; }, "json object and payload not received", 100);
        
        var newPayload;
        runs(function() {
            var payloadJo = JSON.parse(textEncoding$getString(payload, MslConstants$DEFAULT_CHARSET));
	        payloadJo[KEY_DATA] = "x";
	        var plaintext = textEncoding$getBytes(JSON.stringify(payloadJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.encrypt(plaintext, {
	        	result: function(data) { newPayload = data; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return newPayload; }, "newPayload not received", 100);

        var signature;
        runs(function() {
        	CRYPTO_CONTEXT.sign(newPayload, {
        		result: function(data) { signature = data; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", 100);
        
        var exception;
        runs(function() {
        	jo[KEY_PAYLOAD] = base64$encode(newPayload);
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(e) { exception = e; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.PAYLOAD_DATA_CORRUPT));
        });
    });
    
    // large data requires a longer timeout
    it("large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 3000);
        
        var joChunk;
        runs(function() {
            expect(chunk.data).toEqual(largedata);
            var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 3000);
        runs(function() {
        	expect(joChunk.data).toEqual(chunk.data);
        });
    });
    
    // large data requires a longer timeout
    xit("GZIP large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 3000);
        
        var joChunk;
        runs(function() {
            expect(chunk.data).toEqual(largedata);
            
            // Random data will not compress.
            expect(chunk.compressionAlgo).toBeNull();
            
            var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 3000);
        runs(function() {
        	expect(joChunk.data).toEqual(chunk.data);
        	expect(joChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });
    
    xit("GZIP verona", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, rawdata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var joChunk;
        runs(function() {
            expect(chunk.data).toEqual(data);
            
            // Romeo and Juliet will compress.
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.GZIP.toString());
            
            var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 100);
        runs(function() {
        	expect(joChunk.data).toEqual(chunk.data);
        	expect(joChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });
    
    // large data requires a longer timeout
    it("LZW large data", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, largedata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 3000);
        
        var joChunk;
        runs(function() {
            expect(chunk.data).toEqual(largedata);
            
            // Random data will not compress.
            expect(chunk.compressionAlgo).toBeNull();
            
            var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 3000);
        runs(function() {
        	expect(joChunk.data).toEqual(chunk.data);
        	expect(joChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });
    
    xit("LZW verona", function() {
        var chunk;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, rawdata, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        var joChunk;
        runs(function() {
            expect(chunk.data).toEqual(data);
            
            // Romeo and Juliet will compress.
            expect(chunk.compressionAlgo).toEqual(CompressionAlgorithm.LZW.toString());
            
            var jo = JSON.parse(JSON.stringify(chunk));
            PayloadChunk$parse(jo, CRYPTO_CONTEXT, {
                result: function(x) { joChunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joChunk; }, "joChunk not received", 100);
        runs(function() {
        	expect(joChunk.data).toEqual(chunk.data);
        	expect(joChunk.compressionAlgo).toEqual(chunk.compressionAlgo);
        });
    });
    
    xit("equals sequence number", function() {
        var seqNoA = 1;
        var seqNoB = 2;
        var chunkA = undefined, chunkB;
        runs(function() {
            PayloadChunk$create(seqNoA, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(seqNoB, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks not received", 100);
        var chunkA2;
        runs(function() {
            PayloadChunk$parse(JSON.parse(JSON.stringify(chunkA)), CRYPTO_CONTEXT, {
                result: function(x) { chunkA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2 not received", 100);
        
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
        var chunkA = undefined, chunkB;
        runs(function() {
            PayloadChunk$create(SEQ_NO, msgIdA, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(SEQ_NO, msgIdB, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks not received", 100);
        var chunkA2;
        runs(function() {
            PayloadChunk$parse(JSON.parse(JSON.stringify(chunkA)), CRYPTO_CONTEXT, {
                result: function(x) { chunkA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2 not received", 100);
        
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
        var chunkA = undefined, chunkB;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(SEQ_NO, MSG_ID, false, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks not received", 100);
        var chunkA2;
        runs(function() {
            PayloadChunk$parse(JSON.parse(JSON.stringify(chunkA)), CRYPTO_CONTEXT, {
                result: function(x) { chunkA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2 not received", 100);
        
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
        var chunkA = undefined, chunkB;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB; }, "chunks not received", 100);
        var chunkA2;
        runs(function() {
            PayloadChunk$parse(JSON.parse(JSON.stringify(chunkA)), CRYPTO_CONTEXT, {
                result: function(x) { chunkA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2 not received", 100);
        
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
        var chunkA = undefined, chunkB = undefined, chunkC;
        runs(function() {
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, dataA, CRYPTO_CONTEXT, {
                result: function(x) { chunkA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, dataB, CRYPTO_CONTEXT, {
                result: function(x) { chunkB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, dataC, CRYPTO_CONTEXT, {
                result: function(x) { chunkC = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA && chunkB && chunkC; }, "chunks not received", 100);
        var chunkA2;
        runs(function() {
            PayloadChunk$parse(JSON.parse(JSON.stringify(chunkA)), CRYPTO_CONTEXT, {
                result: function(x) { chunkA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunkA2; }, "chunkA2 not received", 100);
        
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
            PayloadChunk$create(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk not received", 100);
        
        runs(function() {
	        expect(chunk.equals(null)).toBeFalsy();
	        expect(chunk.equals(CRYPTO_CONTEXT_ID)).toBeFalsy();
	        expect(chunk.uniqueKey() != CRYPTO_CONTEXT_ID.uniqueKey()).toBeTruthy();
        });
    });
});
