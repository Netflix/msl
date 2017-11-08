/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
 * MSL signature envelope unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MslSignatureEnvelope", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslSignatureEnvelope = require('msl-core/crypto/MslSignatureEnvelope.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslConstants = require('msl-core/MslConstants.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /**  version. */
    var KEY_VERSION = "version";
    /**  algorithm. */
    var KEY_ALGORITHM = "algorithm";
    /**  signature. */
    var KEY_SIGNATURE = "signature";
    
    // Shortcuts.
    var Version = MslSignatureEnvelope.Version;
    
    var SIGNATURE = new Uint8Array(32);
    
    /** MSL encoder factory. */
    var encoder;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            var ctx;
            runs(function() {
                var random = new Random();
                random.nextBytes(SIGNATURE);
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
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
                MslSignatureEnvelope.create(SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var envelopeBytes;
            runs(function() {
                expect(envelope.algorithm).toBeNull();
                expect(envelope.signature).toEqual(SIGNATURE);
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                expect(envelopeBytes).not.toBeNull();

                MslSignatureEnvelope.parse(envelopeBytes, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);

            var moEnvelopeBytes;
            runs(function() {
                expect(moEnvelope.algorithm).toEqual(envelope.algorithm);
                expect(moEnvelope.signature).toEqual(envelope.signature);
                moEnvelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEnvelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelopeBytes; }, "moEnvelopeBytes", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelopeBytes).toEqual(envelopeBytes);
            });
        });
        
        it("encode is correct", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(envelopeBytes).not.toBeNull();
                expect(envelopeBytes).toEqual(SIGNATURE);
            });
        });
    });
    
    function data() {
        var keys = Object.keys(MslConstants.SignatureAlgo); 
        return keys.map(function(key) {
            return [ MslConstants.SignatureAlgo[key] ];
        });
    }
    
    parameterize("version 2", data, function(algorithm) {
        it("ctors", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var envelopeBytes;
            runs(function() {
                expect(envelope.algorithm).toEqual(algorithm);
                expect(envelope.signature).toEqual(SIGNATURE);
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                expect(envelopeBytes).not.toBeNull();

                MslSignatureEnvelope.parse(envelopeBytes, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);

            var moEnvelopeBytes;
            runs(function() {
                expect(moEnvelope.algorithm).toEqual(envelope.algorithm);
                expect(moEnvelope.signature).toEqual(envelope.signature);
                moEnvelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { moEnvelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelopeBytes; }, "moEnvelopeBytes", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelopeBytes).toEqual(envelopeBytes);
            });
        });
        
        it("encode is correct", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                
                expect(mo.getInt(KEY_VERSION)).toEqual(Version.V2);
                expect(mo.getString(KEY_ALGORITHM)).toEqual(algorithm.toString());
                expect(mo.getBytes(KEY_SIGNATURE)).toEqual(SIGNATURE);
            });
        });
        
        it("missing version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);
            
            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);
            
            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.remove(KEY_VERSION);
                
                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
        
        it("invalid version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);

            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.put(KEY_VERSION, "x");
                
                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
        
        it("unknown version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);

            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.put(KEY_VERSION, -1);

                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
        
        it("missing algorithm", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);

            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.remove(KEY_ALGORITHM);

                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
        
        it("invalid algorithm", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);

            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.put(KEY_ALGORITHM, "x");

                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
        
        it("missing signature", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope.create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var envelopeBytes;
            runs(function() {
                envelope.getBytes(encoder, ENCODER_FORMAT, {
                    result: function(x) { envelopeBytes = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelopeBytes; }, "envelopeBytes", MslTestConstants.TIMEOUT);

            var moEncode;
            runs(function() {
                var mo = encoder.parseObject(envelopeBytes);
                mo.remove(KEY_SIGNATURE);

                encoder.encodeObject(mo, ENCODER_FORMAT, {
                	result: function(x) { moEncode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
            
            var moEnvelope;
            runs(function() {
                MslSignatureEnvelope.parse(moEncode, null, encoder, {
                    result: function(x) { moEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return moEnvelope; }, "moEnvelope", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(moEnvelope.algorithm).toBeNull();
                expect(moEnvelope.signature).toEqual(moEncode);
            });
        });
    });
});
