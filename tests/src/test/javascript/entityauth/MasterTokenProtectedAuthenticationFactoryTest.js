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
 * Master token protected authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MasterTokenProtectedAuthenticationFactory", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MasterTokenProtectedAuthenticationFactory = require('msl-core/entityauth/MasterTokenProtectedAuthenticationFactory.js');
    var MasterTokenProtectedAuthenticationData = require('msl-core/entityauth/MasterTokenProtectedAuthenticationData.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /**
     * Key master token.
     * 
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    
    var IDENTITY = "identity";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Authentication utilities. */
    var authutils;
    /** Entity authentication factory. */
    var factory;

    /** Master token. */
    var masterToken;
    /** Encapsulated entity authentication data. */
    var eAuthdata;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                authutils = new MockAuthenticationUtils();
                factory = new MasterTokenProtectedAuthenticationFactory(authutils);
                ctx.addEntityAuthenticationFactory(factory);
                
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { masterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
            });
            waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT);
        }
    });
    
    afterEach(function() {
        authutils.reset();
    });
    
    it("create data", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var moAuthdata;
        runs(function() {
            factory.createData(ctx, authdata, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            expect(moAuthdata instanceof MasterTokenProtectedAuthenticationData).toBeTruthy();
            var moData = moAuthdata;
            expect(moData.getIdentity()).toEqual(data.getIdentity());
            expect(moData.scheme).toEqual(data.scheme);
            expect(moData.encapsulatedAuthdata).toEqual(data.encapsulatedAuthdata);
        });
    });
    
    it("encode exception", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            authdata.remove(KEY_MASTER_TOKEN);
            factory.createData(ctx, authdata, {
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
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        var cryptoContext, eCryptoContext;
        var plaintext, ciphertext, eCiphertext;
        runs(function() {
            cryptoContext = factory.getCryptoContext(ctx, data);
            expect(cryptoContext).not.toBeNull();
            
            var eFactory = ctx.getEntityAuthenticationFactory(eAuthdata.scheme);
            eCryptoContext = eFactory.getCryptoContext(ctx, eAuthdata);
            expect(eCryptoContext).not.toBeNull();
            
            plaintext = new Uint8Array(32);
            ctx.getRandom().nextBytes(plaintext);
            
            cryptoContext.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { ciphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            eCryptoContext.encrypt(plaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { eCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ciphertext && eCiphertext; }, "ciphertext", MslTestConstants.TIMEOUT);
        
        var decrypted, eDecrypted;
        runs(function() {
            cryptoContext.decrypt(eCiphertext, encoder, {
                result: function(x) { decrypted = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            eCryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { eDecrypted = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return decrypted && eDecrypted; }, "decrypted", MslTestConstants.TIMEOUT);
        
        var signature, eSignature;
        runs(function() {
            expect(decrypted).toEqual(plaintext);
            expect(eDecrypted).toEqual(plaintext);
            
            cryptoContext.sign(plaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { signature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            eCryptoContext.sign(plaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { eSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature && eSignature; }, "decrypted", MslTestConstants.TIMEOUT);
        
        var verified, eVerified;
        runs(function() {
            cryptoContext.verify(plaintext, eSignature, encoder, {
                result: function(x) { verified = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            eCryptoContext.verify(plaintext, signature, encoder, {
                result: function(x) { eVerified = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified && eVerified; }, "decrypted", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(verified).toBeTruthy();
            expect(eVerified).toBeTruthy();
        });
    });
    
    it("unsupported encapsulated scheme", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
        
        var data;
        runs(function() {
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);

            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
        });
    });
    
    it("revoked", function() {
        var data;
        runs(function() {
            authutils.revokeEntity(IDENTITY);
            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_REVOKED));
        });
    });
    
    it("scheme not permitted", function() {
        var data;
        runs(function() {
            authutils.disallowScheme(IDENTITY, EntityAuthenticationScheme.MT_PROTECTED);
            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA));
        });
    });
});