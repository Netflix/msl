/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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

const MslEncoderFormat = require('../../../../../core/src/main/javascript/io/MslEncoderFormat.js');
const EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
const MasterTokenProtectedAuthenticationFactory = require('../../../../../core/src/main/javascript/entityauth/MasterTokenProtectedAuthenticationFactory.js');
const UnauthenticatedAuthenticationData = require('../../../../../core/src/main/javascript/entityauth/UnauthenticatedAuthenticationData.js');
const MslEncodingException = require('../../../../../core/src/main/javascript/MslEncodingException.js');
const MslEntityAuthException = require('../../../../../core/src/main/javascript/MslEntityAuthException.js');
const MslError = require('../../../../../core/src/main/javascript/MslError.js');

const MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
const MockAuthenticationUtils = require('../../../main/javascript/util/MockAuthenticationUtils.js');
const MslTestUtils = require('../../../main/javascript/util/MslTestUtils.js');

describe("MasterTokenProtectedAuthenticationFactory", function() {
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
            waitsFor(function() { return ctx; }, "ctx", 100);
            
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
            waitsFor(function() { return masterToken; }, "master token", 100);
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
        waitsFor(function() { return data; }, "data", 100);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);
        
        var moAuthdata;
        runs(function() {
            factory.createData(ctx, authdata, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", 100);
        
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
        waitsFor(function() { return data; }, "data", 100);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);
        
        var exception;
        runs(function() {
            authdata.remove(KEY_MASTER_TOKEN);
            factory.createData(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
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
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var cryptoContext = factory.getCryptoContext(ctx, data);
            expect(cryptoContext).not.toBeNull();
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
        waitsFor(function() { return ctx; }, "ctx", 100);
        
        var data;
        runs(function() {
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);

            MasterTokenProtectedAuthenticationData.create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
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
        waitsFor(function() { return data; }, "data", 100);
        
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
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA));
        });
    });
});