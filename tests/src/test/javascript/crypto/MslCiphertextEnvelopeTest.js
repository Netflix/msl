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
describe("MslCiphertextEnvelope", function() {
    /** JSON key version. */
    var KEY_VERSION = "version";
    /** JSON key key ID. */
    var KEY_KEY_ID = "keyid";
    /** JSON key cipherspec. */
    var KEY_CIPHERSPEC = "cipherspec";
    /** JSON key initialization vector. */
    var KEY_IV = "iv";
    /** JSON key ciphertext. */
    var KEY_CIPHERTEXT = "ciphertext";
    /** JSON key SHA-256. */
    var KEY_SHA256 = "sha256";
    
	/** Key ID. */
	var KEY_ID = "keyid";
	
	// Shortcuts
	var Version = MslCiphertextEnvelope$Version;
	
	var random = new Random();
	var IV = new Uint8Array(16);
	random.nextBytes(IV);
	var CIPHERTEXT = new Uint8Array(32);
	random.nextBytes(CIPHERTEXT);
	
	describe("version 1", function() {
        it("ctors", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var json, joEnvelope;
            runs(function() {
                expect(envelope.keyId).toEqual(KEY_ID);
                expect(envelope.cipherSpec).toBeNull();
                expect(envelope.iv).toEqual(IV);
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                json = JSON.stringify(envelope);
                expect(json).not.toBeNull();
                
                var jo = JSON.parse(json);
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.keyId).toEqual(envelope.keyId);
                expect(joEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(joEnvelope.iv).toEqual(envelope.iv);
                expect(joEnvelope.ciphertext).toEqual(envelope.ciphertext);
                var joJson = JSON.stringify(joEnvelope);
                expect(joJson).toEqual(json);
            });
        });

        it("ctors with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var json, joEnvelope;
            runs(function() {
                expect(envelope.keyId).toEqual(KEY_ID);
                expect(envelope.cipherSpec).toBeNull();
                expect(envelope.iv).toBeNull();
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                json = JSON.stringify(envelope);
                expect(json).not.toBeNull();

                var jo = JSON.parse(json);
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.keyId).toEqual(envelope.keyId);
                expect(joEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(joEnvelope.iv).toEqual(envelope.iv);
                expect(joEnvelope.ciphertext).toEqual(envelope.ciphertext);
                var joJson = JSON.stringify(joEnvelope);
                expect(joJson).toEqual(json);
            });
        });

        it("json is correct", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                
                expect(jo[KEY_KEY_ID]).toEqual(KEY_ID);
                expect(jo[KEY_CIPHERSPEC]).toBeFalsy();
                expect(base64$decode(jo[KEY_IV])).toEqual(IV);
                expect(base64$decode(jo[KEY_CIPHERTEXT])).toEqual(CIPHERTEXT);
            });
        });

        it("json is correct with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                
                expect(jo[KEY_KEY_ID]).toEqual(KEY_ID);
                expect(jo[KEY_CIPHERSPEC]).toBeFalsy();
                expect(jo[KEY_IV]).toBeFalsy();
                expect(base64$decode(jo[KEY_CIPHERTEXT])).toEqual(CIPHERTEXT);
            });
        });
        
        it("missing key ID", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_KEY_ID];
                
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
        
        it("missing ciphertext", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_CIPHERTEXT];
                
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
        
        it("missing SHA-256", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_SHA256];

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });

        it("incorrect SHA-256", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(KEY_ID, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joEnvelope;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                var hash = base64$decode(jo[KEY_SHA256]);
                expect(hash).not.toBeNull();
                hash[0] += 1;
                jo[KEY_SHA256] = base64$encode(hash);

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.keyId).toEqual(KEY_ID);
                expect(joEnvelope.cipherSpec).toBeNull();
                expect(joEnvelope.iv).toEqual(IV);
                expect(joEnvelope.ciphertext).toEqual(CIPHERTEXT);
            });
        });
	});
	
	function data() {
	    var keys = Object.keys(MslConstants$CipherSpec); 
	    return keys.map(function(key) {
	        return [ MslConstants$CipherSpec[key] ];
	    });
	}

	parameterize("version 2", data, function(cipherSpec) {
	    it("ctors", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            var json, joEnvelope;
            runs(function() {
                expect(envelope.keyId).toBeNull();
                expect(envelope.cipherSpec).toEqual(cipherSpec);
                expect(envelope.iv).toEqual(IV);
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                json = JSON.stringify(envelope);
                expect(json).not.toBeNull();

                var jo = JSON.parse(json);
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.keyId).toEqual(envelope.keyId);
                expect(joEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(joEnvelope.iv).toEqual(envelope.iv);
                expect(joEnvelope.ciphertext).toEqual(envelope.ciphertext);
                var joJson = JSON.stringify(joEnvelope);
                expect(joJson).toEqual(json);
            });
        });

        it("ctors with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var json, joEnvelope;
            runs(function() {
                expect(envelope.keyId).toBeNull();
                expect(envelope.cipherSpec).toEqual(cipherSpec);
                expect(envelope.iv).toBeNull();
                expect(envelope.ciphertext).toEqual(CIPHERTEXT);
                json = JSON.stringify(envelope);
                expect(json).not.toBeNull();

                var jo = JSON.parse(json);
                MslCiphertextEnvelope$parse(jo, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.keyId).toEqual(envelope.keyId);
                expect(joEnvelope.cipherSpec).toEqual(envelope.cipherSpec);
                expect(joEnvelope.iv).toEqual(envelope.iv);
                expect(joEnvelope.ciphertext).toEqual(envelope.ciphertext);
                var joJson = JSON.stringify(joEnvelope);
                expect(joJson).toEqual(json);
            });
        });

        it("json is correct", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
    
                expect(parseInt(jo[KEY_VERSION])).toEqual(Version.V2);
                expect(jo[KEY_KEY_ID]).toBeFalsy();
                expect(jo[KEY_CIPHERSPEC]).toEqual(cipherSpec);
                expect(base64$decode(jo[KEY_IV])).toEqual(IV);
                expect(base64$decode(jo[KEY_CIPHERTEXT])).toEqual(CIPHERTEXT);
            });
        });

        it("json is correct with null IV", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, null, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
    
                expect(parseInt(jo[KEY_VERSION])).toEqual(Version.V2);
                expect(jo[KEY_KEY_ID]).toBeFalsy();
                expect(jo[KEY_CIPHERSPEC]).toEqual(cipherSpec);
                expect(jo[KEY_IV]).toBeFalsy();
                expect(base64$decode(jo[KEY_CIPHERTEXT])).toEqual(CIPHERTEXT);
            });
        });
        
        it("missing version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_VERSION];

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
        
        it("invalid version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                jo[KEY_VERSION] = "x";

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
        
        it("unknown version", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                jo[KEY_VERSION] = -1;

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE));
            });
        });
        
        it("missing cipher specification", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_CIPHERSPEC];

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
        
        it("invalid cipher specification", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                jo[KEY_CIPHERSPEC] = "x";

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_CIPHERSPEC));
            });
        });
        
        it("missing ciphertext", function() {
            var envelope;
            runs(function() {
                MslCiphertextEnvelope$create(cipherSpec, IV, CIPHERTEXT, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var exception;
            runs(function() {
                var json = JSON.stringify(envelope);
                var jo = JSON.parse(json);
                delete jo[KEY_CIPHERTEXT];

                MslCiphertextEnvelope$parse(jo, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; },"exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
            });
        });
	});
});