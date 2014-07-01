/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
    /** JSON key version. */
    var KEY_VERSION = "version";
    /** JSON key algorithm. */
    var KEY_ALGORITHM = "algorithm";
    /** JSON key signature. */
    var KEY_SIGNATURE = "signature";
    
    // Shortcuts.
    var Version = MslSignatureEnvelope$Version;
    
    var random = new Random();
    var SIGNATURE = new Uint8Array(32);
    random.nextBytes(SIGNATURE);

    describe("version 1", function() {
        it("ctors", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            var envelopeBytes, joEnvelope;
            runs(function() {
                expect(envelope.algorithm).toBeNull();
                expect(envelope.signature).toEqual(SIGNATURE);
                envelopeBytes = envelope.bytes;
                expect(envelopeBytes).not.toBeNull();

                MslSignatureEnvelope$parse(envelopeBytes, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);

            runs(function() {
                expect(joEnvelope.algorithm).toEqual(envelope.algorithm);
                expect(joEnvelope.signature).toEqual(envelope.signature);
                var joEnvelopeBytes = joEnvelope.bytes;
                expect(joEnvelopeBytes).toEqual(envelopeBytes);
            });
        });
        
        it("json is correct", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var envelopeBytes = envelope.bytes;
                expect(envelopeBytes).not.toBeNull();
                expect(envelopeBytes).toEqual(SIGNATURE);
            });
        });
    });
    
    function data() {
        var keys = Object.keys(MslConstants$SignatureAlgo); 
        return keys.map(function(key) {
            return [ MslConstants$SignatureAlgo[key] ];
        });
    }
    
    parameterize("version 2", data, function(algorithm) {
        it("ctors", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            var envelopeBytes, joEnvelope;
            runs(function() {
                expect(envelope.algorithm).toEqual(algorithm);
                expect(envelope.signature).toEqual(SIGNATURE);
                envelopeBytes = envelope.bytes;
                expect(envelopeBytes).not.toBeNull();

                MslSignatureEnvelope$parse(envelopeBytes, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toEqual(envelope.algorithm);
                expect(joEnvelope.signature).toEqual(envelope.signature);
                var joEnvelopeBytes = joEnvelope.bytes;
                expect(joEnvelopeBytes).toEqual(envelopeBytes);
            });
        });
        
        it("json is correct", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                
                expect(parseInt(jo[KEY_VERSION])).toEqual(Version.V2);
                expect(jo[KEY_ALGORITHM]).toEqual(algorithm.toString());
                expect(base64$decode(jo[KEY_SIGNATURE])).toEqual(SIGNATURE);
            });
        });
        
        it("missing version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);
            
            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                delete jo[KEY_VERSION];
                
                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
        
        it("invalid version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                jo[KEY_VERSION] = "x";
                
                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
        
        it("unknown version", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                jo[KEY_VERSION] = "-1";

                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
        
        it("missing algorithm", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                delete jo[KEY_ALGORITHM];

                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
        
        it("invalid algorithm", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                jo[KEY_ALGORITHM] = "x";

                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
        
        it("missing signature", function() {
            var envelope;
            runs(function() {
                MslSignatureEnvelope$create(algorithm, SIGNATURE, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", 100);

            var joJson, joEnvelope;
            runs(function() {
                var envelopeBytes = envelope.bytes;
                var jo = JSON.parse(textEncoding$getString(envelopeBytes, MslConstants$DEFAULT_CHARSET));
                delete jo[KEY_SIGNATURE];

                joJson = textEncoding$getBytes(JSON.stringify(jo), MslConstants$DEFAULT_CHARSET);
                MslSignatureEnvelope$parse(joJson, null, {
                    result: function(x) { joEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joEnvelope; }, "joEnvelope", 100);
            
            runs(function() {
                expect(joEnvelope.algorithm).toBeNull();
                expect(joEnvelope.signature).toEqual(joJson);
            });
        });
    });
});
