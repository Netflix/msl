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
 * Unauthenticated suffixed authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UnauthenticatedSuffixedAuthenticationFactory", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var UnauthenticatedSuffixedAuthenticationFactory = require('msl-core/entityauth/UnauthenticatedSuffixedAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UnauthenticatedSuffixedAuthenticationData = require('msl-core/entityauth/UnauthenticatedSuffixedAuthenticationData.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key root. */
    var KEY_ROOT = "root";
    
    var UNAUTHENTICATED_ROOT = "MOCKUNAUTH-ROOT";
    var UNAUTHENTICATED_SUFFIX = "MOCKUNAUTH-SUFFIX";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Entity authentication factory. */
    var factory = new UnauthenticatedSuffixedAuthenticationFactory();
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.NONE_SUFFIXED, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    it("createData", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(UNAUTHENTICATED_ROOT, UNAUTHENTICATED_SUFFIX);

        var entityAuthMo;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", MslTestConstants.TIMEOUT);

        var authdata;
        runs(function() {
            factory.createData(ctx, entityAuthMo, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);

        var dataMo, authdataMo;
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof UnauthenticatedSuffixedAuthenticationData).toBeTruthy();
            
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { dataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.toMslObject(encoder, authdata, {
                result: function(x) { authdataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataMo && authdataMo; }, "dataMo && authdataMo", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(MslEncoderUtils.equalObjects(dataMo, authdataMo)).toBeTruthy();
        });
    });
    
    it("encode exception", function() {
        var entityAuthMo;
        runs(function() {
        	var data = new UnauthenticatedSuffixedAuthenticationData(UNAUTHENTICATED_ROOT, UNAUTHENTICATED_SUFFIX);
        	data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            entityAuthMo.remove(KEY_ROOT);
            factory.createData(ctx, entityAuthMo, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("crypto context", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(UNAUTHENTICATED_ROOT, UNAUTHENTICATED_SUFFIX);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
});