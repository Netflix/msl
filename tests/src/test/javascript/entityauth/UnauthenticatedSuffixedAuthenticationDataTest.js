/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * Unauthenticated suffixed entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UnauthenticatedSuffixedAuthenticationData", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UnauthenticatedSuffixedAuthenticationData = require('msl-core/entityauth/UnauthenticatedSuffixedAuthenticationData.js');
    var EntityAuthenticationData = require('msl-core/entityauth/EntityAuthenticationData.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    
    /** Key entity root. */
    var KEY_ROOT = "root";
    /** Key entity suffix. */
    var KEY_SUFFIX = "suffix";
    
    /** Identity concatenation character. */
    var CONCAT_CHAR = ".";
    
    var ROOT = "root";
    var SUFFIX = "suffix";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.X509, false, {
                    result: function(c) { ctx = c; },
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

    it("ctors", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        expect(data.getIdentity()).toEqual(ROOT + CONCAT_CHAR + SUFFIX);
        expect(data.root).toEqual(ROOT);
        expect(data.suffix).toEqual(SUFFIX);
        expect(data.scheme).toEqual(EntityAuthenticationScheme.NONE_SUFFIXED);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var encode;
        runs(function() {
            expect(authdata).not.toBeNull();
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moData, moAuthdata;
        runs(function() {
            expect(encode).not.toBeNull();
        
            moData = UnauthenticatedSuffixedAuthenticationData.parse(authdata);
            expect(moData.getIdentity()).toEqual(data.getIdentity());
            expect(moData.root).toEqual(data.root);
            expect(moData.suffix).toEqual(data.suffix);
            expect(moData.scheme).toEqual(data.scheme);
            moData.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            expect(moAuthdata).toEqual(authdata);
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
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
    
    it("mslobject is correct", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(mo.getString(KEY_SCHEME)).toEqual(EntityAuthenticationScheme.NONE_SUFFIXED.name);
            var authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
            expect(authdata.getString(KEY_ROOT)).toEqual(ROOT);
            expect(authdata.getString(KEY_SUFFIX)).toEqual(SUFFIX);
        });
    });
    
    it("create", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        
        var encode;
        runs(function() {
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        var entitydata;
        runs(function() {
            EntityAuthenticationData.parse(ctx, mo, {
                result: function(x) { entitydata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return entitydata; }, "entitydata", MslTestConstants.TIMEOUT);

        var moData, moAuthdata;
        runs(function() {
            expect(entitydata).not.toBeNull();
            expect(entitydata instanceof UnauthenticatedSuffixedAuthenticationData).toBeTruthy();
            
            moData = entitydata;
            expect(moData.getIdentity()).toEqual(data.getIdentity());
            expect(moData.root).toEqual(data.root);
            expect(moData.suffix).toEqual(data.suffix);
            expect(moData.scheme).toEqual(data.scheme);
            moData.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            expect(moAuthdata).toEqual(authdata);
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
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
    
    it("missing root", function() {
        var authdata;
        runs(function() {
	        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
            authdata.remove(KEY_ROOT);
            var f = function() {
                UnauthenticatedSuffixedAuthenticationData.parse(authdata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("missing suffix", function() {
        var authdata;
        runs(function() {
            var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
            authdata.remove(KEY_SUFFIX);
            var f = function() {
                UnauthenticatedSuffixedAuthenticationData.parse(authdata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("equals root", function() {
        var dataA, dataB, dataA2;
        runs(function() {
            dataA = new UnauthenticatedSuffixedAuthenticationData(ROOT + "A", SUFFIX);
            dataB = new UnauthenticatedSuffixedAuthenticationData(ROOT + "B", SUFFIX);
            MslTestUtils.toMslObject(encoder, dataA, {
                result: function(mo) {
                    EntityAuthenticationData.parse(ctx, mo, {
                        result: function(x) { dataA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });

    it("equals suffix", function() {
        var dataA, dataB, dataA2;
        runs(function() {
            dataA = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX + "A");
            dataB = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX + "B");
            MslTestUtils.toMslObject(encoder, dataA, {
                result: function(mo) {
                    EntityAuthenticationData.parse(ctx, mo, {
                        result: function(x) { dataA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals object", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_ROOT)).toBeFalsy();
    });
});
