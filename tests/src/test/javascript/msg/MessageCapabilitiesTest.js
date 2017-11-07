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
 * Message capabilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageCapabilities", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var Arrays = require('msl-core/util/Arrays.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key compression algorithms. */
    var KEY_COMPRESSION_ALGOS = "compressionalgos";
    /** Key encoder formats. */
    var KEY_ENCODER_FORMATS = "encoderformats";
    
    // Shortcuts
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;
    
    var ALGOS = [ CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW ];
    var LANGUAGES = [ "en-US", "es" ];
    var FORMATS = [ MslEncoderFormat.JSON ];
    
    /** MSL encoder factory. */
    var encoder;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            var ctx;
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                initialized = true;
            });
        }
    });
    
    it("ctors", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        expect(caps.compressionAlgorithms).toEqual(ALGOS);
        expect(caps.languages).toEqual(LANGUAGES);
        expect(caps.encoderFormats).toEqual(FORMATS);
        
        var encode;
        runs(function() {
            caps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moCaps, moEncode;
        runs(function() {
            expect(encode).not.toBeNull();

            moCaps = MessageCapabilities.parse(encoder.parseObject(encode));
            expect(moCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
            expect(moCaps.languages).toEqual(caps.languages);
            expect(moCaps.encoderFormats).toEqual(caps.encoderFormats);
            moCaps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            // This test will not always pass since set data is unordered.
            //expect(moEncode).toEqual(encode);
            var mo2Caps = MessageCapabilities.parse(encoder.parseObject(moEncode));
            expect(mo2Caps).toEqual(moCaps);
        });
    });
    
    it("ctors with null algorithms", function() {
        var caps = new MessageCapabilities(null, LANGUAGES, FORMATS);
        var algos = caps.compressionAlgorithms;
        expect(algos).not.toBeNull();
        expect(algos.length).toEqual(0);
        expect(caps.languages).toEqual(LANGUAGES);
        expect(caps.encoderFormats).toEqual(FORMATS);
        
        var encode;
        runs(function() {
            caps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moCaps, moEncode;
        runs(function() {
            expect(encode).not.toBeNull();
            
            moCaps = MessageCapabilities.parse(encoder.parseObject(encode));
            expect(moCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
            expect(moCaps.languages).toEqual(caps.languages);
            expect(moCaps.encoderFormats).toEqual(caps.encoderFormats);
            moCaps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            // This test will not always pass since set data is unordered.
            //expect(moEncode).toEqual(encode);
            var mo2Caps = MessageCapabilities.parse(encoder.parseObject(moEncode));
            expect(mo2Caps).toEqual(moCaps);
        });
    });
    
    it("unknown compression algorithm", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, caps, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var ma = mo.getMslArray(KEY_COMPRESSION_ALGOS);
            ma.put(-1, "CATZ");
            mo.put(KEY_COMPRESSION_ALGOS, ma);
        
            var moCaps = MessageCapabilities.parse(mo);
            expect(moCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
        });
    });
    
    it("ctors with null languages", function() {
        var caps = new MessageCapabilities(ALGOS, null, FORMATS);
        expect(caps.compressionAlgorithms).toEqual(ALGOS);
        var languages = caps.languages;
        expect(languages).not.toBeNull();
        expect(languages.length).toEqual(0);
        expect(caps.encoderFormats).toEqual(FORMATS);
        
        var encode;
        runs(function() {
            caps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moCaps, moEncode;
        runs(function() {
            moCaps = MessageCapabilities.parse(encoder.parseObject(encode));
            expect(moCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
            expect(moCaps.languages).toEqual(caps.languages);
            expect(moCaps.encoderFormats).toEqual(caps.encoderFormats);
            moCaps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            // This test will not always pass since set data is unordered.
            //expect(moEncode).toEqual(encode);
            var mo2Caps = MessageCapabilities.parse(encoder.parseObject(moEncode));
            expect(mo2Caps).toEqual(moCaps);
        });
    });
    
    it("ctors with null encoder formats", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES, null);
        expect(caps.compressionAlgorithms).toEqual(ALGOS);
        expect(caps.languages).toEqual(LANGUAGES);
        var formats = caps.encoderFormats;
        expect(formats).not.toBeNull();
        expect(formats.length).toEqual(0);
        
        var encode;
        runs(function() {
            caps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moCaps, moEncode;
        runs(function() {
            moCaps = MessageCapabilities.parse(encoder.parseObject(encode));
            expect(moCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
            expect(moCaps.languages).toEqual(caps.languages);
            expect(moCaps.encoderFormats).toEqual(caps.encoderFormats);
            moCaps.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            // This test will not always pass since set data is unordered.
            //expect(moEncode).toEqual(encode);
            var mo2Caps = MessageCapabilities.parse(encoder.parseObject(moEncode));
            expect(mo2Caps).toEqual(moCaps);
        });
    });
    
    it("equals compression algorithm", function() {
        var algosA = Arrays.copyOf(ALGOS);
        var algosB = [];
        
        var capsA = new MessageCapabilities(algosA, LANGUAGES, FORMATS);
        var capsB = new MessageCapabilities(algosB, LANGUAGES, FORMATS);
        var capsA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, capsA, {
                result: function(mo) {
                    capsA2 = MessageCapabilities.parse(mo);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return capsA2; }, "capsA2", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(capsA.equals(capsA)).toBeTruthy();
            expect(capsA.uniqueKey()).toEqual(capsA.uniqueKey());
            
            expect(capsA.equals(capsB)).toBeFalsy();
            expect(capsB.equals(capsA)).toBeFalsy();
            expect(capsA.uniqueKey()).not.toEqual(capsB.uniqueKey());
            
            expect(capsA.equals(capsA2)).toBeTruthy();
            expect(capsA2.equals(capsA)).toBeTruthy();
            expect(capsA2.uniqueKey()).toEqual(capsA.uniqueKey());
        });
    });
    
    it("equals languages", function() {
        var langsA = [ "en-US" ];
        var langsB = [ "es" ];
        
        var capsA = new MessageCapabilities(ALGOS, langsA, FORMATS);
        var capsB = new MessageCapabilities(ALGOS, langsB, FORMATS);
        var capsA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, capsA, {
                result: function(mo) {
                    capsA2 = MessageCapabilities.parse(mo);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return capsA2; }, "capsA2", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(capsA.equals(capsA)).toBeTruthy();
            expect(capsA.uniqueKey()).toEqual(capsA.uniqueKey());
            
            expect(capsA.equals(capsB)).toBeFalsy();
            expect(capsB.equals(capsA)).toBeFalsy();
            expect(capsA.uniqueKey()).not.toEqual(capsB.uniqueKey());
            
            expect(capsA.equals(capsA2)).toBeTruthy();
            expect(capsA2.equals(capsA)).toBeTruthy();
            expect(capsA2.uniqueKey()).toEqual(capsA.uniqueKey());
        });
    });
    
    it("equals encoder formats", function() {
        var formatsA = FORMATS;
        var formatsB = [ ];
        
        var capsA = new MessageCapabilities(ALGOS, LANGUAGES, formatsA);
        var capsB = new MessageCapabilities(ALGOS, LANGUAGES, formatsB);
        var capsA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, capsA, {
                result: function(mo) {
                    capsA2 = MessageCapabilities.parse(mo);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return capsA2; }, "capsA2", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(capsA.equals(capsA)).toBeTruthy();
            expect(capsA.uniqueKey()).toEqual(capsA.uniqueKey());
            
            expect(capsA.equals(capsB)).toBeFalsy();
            expect(capsB.equals(capsA)).toBeFalsy();
            expect(capsA.uniqueKey()).not.toEqual(capsB.uniqueKey());
            
            expect(capsA.equals(capsA2)).toBeTruthy();
            expect(capsA2.equals(capsA)).toBeTruthy();
            expect(capsA2.uniqueKey()).toEqual(capsA.uniqueKey());
        });
    });

    it("intersection with self", function() {
        var capsA = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        var capsB = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        var intersection = MessageCapabilities.intersection(capsA, capsB);
        
        expect(intersection).toEqual(capsA);
        expect(intersection).toEqual(capsB);
    });
    
    if("intersection", function() {
        var gzipOnly = [ CompressionAlgorithm.GZIP ];
        var oneLanguage = [ LANGUAGES[0] ];
        var noFormats = [];
        
        var capsA = new MessageCapabilities(ALGOS, oneLanguage, FORMATS);
        var capsB = new MessageCapabilities(gzipOnly, LANGUAGES, FORMATS);
        var capsC = new MessageCapabilities(ALGOS, LANGUAGES, noFormats);
        var intersectionAB = MessageCapabilities.intersection(capsA, capsB);
        var intersectionBA = MessageCapabilities.intersection(capsB, capsA);
        var intersectionAC = MessageCapabilities.intersection(capsA, capsC);
        var intersectionCA = MessageCapabilities.intersection(capsC, capsA);
        var intersectionBC = MessageCapabilities.intersection(capsB, capsC);
        var intersectionCB = MessageCapabilities.intersection(capsC, capsB);
        
        expect(intersectionAB).toEqual(intersectionBA);
        expect(gzipOnly).toEqual(intersectionAB.compressionAlgorithms);
        expect(Arrays.containEachOther(oneLanguage, intersectionAB.languages)).toBeTruthy();
        expect(FORMATS).toEqual(intersectionAB.encoderFormats);
        
        expect(intersectionAC).toEqual(intersectionCA);
        expect(ALGOS).toEqual(intersectionAC.compressionAlgorithms);
        expect(Arrays.containEachOther(oneLanguage, intersectionAC.languages)).toBeTruthy();
        expect(noFormats).toEqual(intersectionAC.encoderFormats);
        
        expect(intersectionBC).toEqual(intersectionCB);
        expect(gzipOnly).toEqual(intersectionBC.compressionAlgorithms);
        expect(Arrays.containEachOther(LANGUAGES, intersectionBC.languages)).toBeTruthy();
        expect(noFormats).toEqual(intersectionBC.encoderFormats);
    });
    
    it("intersection with null capabilities", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        var intersectionA = MessageCapabilities.intersection(null, caps);
        var intersectionB = MessageCapabilities.intersection(caps, null);
        
        expect(intersectionA).toBeNull();
        expect(intersectionB).toBeNull();
    });
});
