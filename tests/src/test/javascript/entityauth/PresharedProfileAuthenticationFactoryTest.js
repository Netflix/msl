/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * Pre-shared keys profile entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PresharedProfileAuthenticationFactory", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var PresharedProfileAuthenticationFactory = require('msl-core/entityauth/PresharedProfileAuthenticationFactory.js');
    var PresharedProfileAuthenticationData = require('msl-core/entityauth/PresharedProfileAuthenticationData.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockKeySetStore = require('msl-tests/entityauth/MockKeySetStore.js');
    var MockPresharedProfileAuthenticationFactory = require('msl-tests/entityauth/MockPresharedProfileAuthenticationFactory.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity preshared keys identity. */
    var KEY_PSKID = "pskid";

    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Authentication utilities. */
    var authutils = new MockAuthenticationUtils();
    /** Entity authentication factory. */
    var factory;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                var store = new MockKeySetStore();
                store.addKeys(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.KPE, MockPresharedProfileAuthenticationFactory.KPH, MockPresharedProfileAuthenticationFactory.KPW);
                factory = new PresharedProfileAuthenticationFactory(store, authutils);
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    afterEach(function() {
        authutils.reset();
    });
    
    it("createData", function () {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
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
            expect(authdata instanceof PresharedProfileAuthenticationData).toBeTruthy();
            
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
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            entityAuthMo.remove(KEY_PSKID);
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
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
    
    it("unknown ESN", function() {
        var f = function() {
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN2, MockPresharedProfileAuthenticationFactory.PROFILE);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_NOT_FOUND));
    });
    
    it("revoked", function() {
        var f = function() {
            authutils.revokeEntity(MockPresharedProfileAuthenticationFactory.PSK_ESN);
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_REVOKED));
    });
});
