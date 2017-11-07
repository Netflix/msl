/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
describe("MslCiphertextEnvelope", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslCiphertextEnvelope = require('msl-core/crypto/MslCiphertextEnvelope.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** Key version. */
    var KEY_VERSION = "version";
    /** Key key ID. */
    var KEY_KEY_ID = "keyid";
    /** Key cipherspec. */
    var KEY_CIPHERSPEC = "cipherspec";
    /** Key initialization vector. */
    var KEY_IV = "iv";
    /** Key ciphertext. */
    var KEY_CIPHERTEXT = "ciphertext";
    /** Key SHA-256. */
    var KEY_SHA256 = "sha256";

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
	/** Key ID. */
	var KEY_ID = "keyid";
	
	// Shortcuts
	var Version = MslCiphertextEnvelope.Version;
	
	var IV = new Uint8Array(16);
	var CIPHERTEXT = new Uint8Array(32);
	
	/** MSL encoder factory. */
	var encoder;
	
	var initialized = false;
	beforeEach(function() {
	    if (!initialized) {
	        var random = new Random();
	        random.nextBytes(IV);
	        random.nextBytes(CIPHERTEXT);

	        var ctx;
	        MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
	            result: function(c) { ctx = c; },
	            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);

	        runs(function() {
	            encoder = ctx.getMslEncoderFactory();
	            initialized = true;
	        });
	    }
	});
	
	describe("version 1", function() {
        it("ctors", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var encode;
            runs(function() {
                expect(envelope.keyId).toEqual(KEY_ID);
                expect(envelope.cipherSpec).toBeNull();
                expect(envelope.iv).toEqual(IV);
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                expect(encode).not.toBeNull();
                var mo = encoder.parseObject(encode);
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            var moEncode;
            runs(function() {
                expect(moEnvelope.keyId).toEqual(envelope.keyId);
                expect(moEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(moEnvelope.iv).toEqual(envelope.iv);
                expect(moEnvelope.ciphertext).toEqual(envelope.ciphertext);
                moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(moEncode).toEqual(encode);
            });
        });

        it("ctors with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var encode;
            runs(function() {
                expect(envelope.keyId).toEqual(KEY_ID);
                expect(envelope.cipherSpec).toBeNull();
                expect(envelope.iv).toBeNull();
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                expect(encode).not.toBeNull();
                var mo = encoder.parseObject(encode);
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            var moEncode;
            runs(function() {
                expect(moEnvelope.keyId).toEqual(envelope.keyId);
                expect(moEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(moEnvelope.iv).toEqual(envelope.iv);
                expect(moEnvelope.ciphertext).toEqual(envelope.ciphertext);
                moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(moEncode).toEqual(encode);
            });
        });

        it("encode is correct", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var mo = encoder.parseObject(encode);
                
                expect(mo.getString(KEY_KEY_ID)).toEqual(KEY_ID);
                expect(mo.has(KEY_CIPHERSPEC)).toBeFalsy();
                expect(mo.getBytes(KEY_IV)).toEqual(IV);
                expect(mo.getBytes(KEY_CIPHERTEXT)).toEqual(CIPHERTEXT);
            });
        });

        it("encode is correct with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var mo = encoder.parseObject(encode);
                
                expect(mo.getString(KEY_KEY_ID)).toEqual(KEY_ID);
                expect(mo.has(KEY_CIPHERSPEC)).toBeFalsy();
                expect(mo.has(KEY_IV)).toBeFalsy();
                expect(mo.getBytes(KEY_CIPHERTEXT)).toEqual(CIPHERTEXT);
            });
        });
        
        it("missing key ID", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_KEY_ID);
                
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("missing ciphertext", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_CIPHERTEXT);
                
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("missing SHA-256", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_SHA256);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("incorrect SHA-256", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var moEnvelope;
            runs(function() {
                var mo = encoder.parseObject(encode);
                var hash = mo.getBytes(KEY_SHA256);
                expect(hash).not.toBeNull();
                hash[0] += 1;
                mo.put(KEY_SHA256, hash);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.keyId).toEqual(KEY_ID);
                expect(moEnvelope.cipherSpec).toBeNull();
                expect(moEnvelope.iv).toEqual(IV);
                expect(moEnvelope.ciphertext).toEqual(CIPHERTEXT);
            });
        });
	});
	
	function data() {
	    var keys = Object.keys(MslConstants.CipherSpec); 
	    return keys.map(function(key) {
	        return [ MslConstants.CipherSpec[key] ];
	    });
	}

	parameterize("version 2", data, function(cipherSpec) {
	    it("ctors", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                expect(envelope.keyId).toBeNull();
                expect(envelope.cipherSpec).toEqual(cipherSpec);
                expect(envelope.iv).toEqual(IV);
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                expect(encode).not.toBeNull();

                var mo = encoder.parseObject(encode);
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            var moEncode;
            runs(function() {
                expect(moEnvelope.keyId).toEqual(envelope.keyId);
                expect(moEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(moEnvelope.iv).toEqual(envelope.iv);
                expect(moEnvelope.ciphertext).toEqual(envelope.ciphertext);
                moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(moEncode).toEqual(encode);
            });
        });

        it("ctors with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var encode;
            runs(function() {
                expect(envelope.keyId).toBeNull();
                expect(envelope.cipherSpec).toEqual(cipherSpec);
                expect(envelope.iv).toBeNull();
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
                
            var moEnvelope;
            runs(function() {
                expect(encode).not.toBeNull();

                var mo = encoder.parseObject(encode);
                MslCiphertextEnvelope.parse(mo, null, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            var moEncode;
            runs(function() {
                expect(moEnvelope.keyId).toEqual(envelope.keyId);
                expect(moEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(moEnvelope.iv).toEqual(envelope.iv);
                expect(moEnvelope.ciphertext).toEqual(envelope.ciphertext);
                moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(moEncode).toEqual(encode);
            });
        });

        it("encode is correct", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var mo = encoder.parseObject(encode);
    
                expect(mo.getInt(KEY_VERSION)).toEqual(Version.V2);
                expect(mo.has(KEY_KEY_ID)).toBeFalsy();
                expect(mo.getString(KEY_CIPHERSPEC)).toEqual(cipherSpec);
                expect(mo.getBytes(KEY_IV)).toEqual(IV);
                expect(mo.getBytes(KEY_CIPHERTEXT)).toEqual(CIPHERTEXT);
            });
        });

        it("encode is correct with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var mo = encoder.parseObject(encode);
    
                expect(mo.getInt(KEY_VERSION)).toEqual(Version.V2);
                expect(mo.has(KEY_KEY_ID)).toBeFalsy();
                expect(mo.getString(KEY_CIPHERSPEC)).toEqual(cipherSpec);
                expect(mo.has(KEY_IV)).toBeFalsy();
                expect(mo.getBytes(KEY_CIPHERTEXT)).toEqual(CIPHERTEXT);
            });
        });
        
        it("missing version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_VERSION);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("invalid version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.put(KEY_VERSION, "x");

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("unknown version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.put(KEY_VERSION, -1);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE));
            });
        });
        
        it("missing cipher specification", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_CIPHERSPEC);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("invalid cipher specification", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.put(KEY_CIPHERSPEC, "x");

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_CIPHERSPEC));
            });
        });
        
        it("missing ciphertext", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope.create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                envelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var mo = encoder.parseObject(encode);
                mo.remove(KEY_CIPHERTEXT);

                MslCiphertextEnvelope.parse(mo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
	});
});