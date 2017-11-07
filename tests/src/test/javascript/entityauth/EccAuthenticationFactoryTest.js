/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
 * ECC asymmetric keys entity authentication factory unit tests.
 *
 */
describe("EccAuthenticationFactory", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslEncoderFactory = require('msl-core/io/MslEncoderFactory.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var EccAuthenticationFactory = require('msl-core/entityauth/EccAuthenticationFactory.js');
    var EccAuthenticationData = require('msl-core/entityauth/EccAuthenticationData.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var EccStore = require('msl-core/entityauth/EccStore.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockEccAuthenticationFactory = require('msl-tests/entityauth/MockEccAuthenticationFactory.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity identity. */
    var KEY_IDENTITY = "identity";

    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Entity authentication factory. */
    var factory;

    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.ECC, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                var keyStore = new EccStore();
                keyStore.addPublicKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PUBKEY);
                factory = new EccAuthenticationFactory(null, keyStore);
                ctx.addEntityAuthenticationFactory(factory);

                initialized = true;
            });
        }
    });

    it("createData", function() {
        var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
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
            expect(authdata instanceof EccAuthenticationData).toBeTruthy();
            
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
            var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            entityAuthMo.remove(KEY_IDENTITY);
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
        var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });

    it("unknown key ID", function() {
        var f = function() {
	        var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, "x");
	        factory.getCryptoContext(ctx, data);
	    };
        expect(f).toThrow(new MslEntityAuthException(MslError.ECC_PUBLICKEY_NOT_FOUND));
    });

    it("local crypto context", function() {
        var keyStore = new EccStore();
        keyStore.addPrivateKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PRIVKEY);
        factory = new EccAuthenticationFactory(MockEccAuthenticationFactory.ECC_PUBKEY_ID, keyStore);
        ctx.addEntityAuthenticationFactory(factory);

        var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        var cryptoContext = factory.getCryptoContext(ctx, data);

        var plaintext = new Uint8Array(16);
        ctx.getRandom().nextBytes(plaintext);
        cryptoContext.sign(plaintext, encoder, ENCODER_FORMAT, {
            result: function(ciphertext) {},
            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        });
    });

    it("missing private key", function() {
        var f = function() {
            var keyStore = new EccStore();
            keyStore.addPublicKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PUBKEY);
            var factory = new EccAuthenticationFactory(MockEccAuthenticationFactory.ECC_PUBKEY_ID, keyStore);

            var data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.ECC_PRIVATEKEY_NOT_FOUND));
    });
});
