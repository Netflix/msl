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

/**
 * RSA asymmetric keys entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("RsaAuthenticationFactory", function() {
    /** JSON key entity identity. */
    var KEY_IDENTITY = "identity";

    /** MSL context. */
    var ctx;
    /** Entity authentication factory. */
    var factory;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.RSA, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
            runs(function() {
                var rsaStore = new RsaStore();
                rsaStore.addPublicKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PUBKEY);
                factory = new RsaAuthenticationFactory(null, rsaStore);
                ctx.addEntityAuthenticationFactory(factory);
                
                initialized = true;
            });
        }
    });
    
    it("createData", function() {
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        var entityAuthJO = data.getAuthData();

        var authdata;
        runs(function() {
            factory.createData(ctx, entityAuthJO, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);

        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof RsaAuthenticationData).toBeTruthy();
            
            var dataJo = JSON.parse(JSON.stringify(data));
            var authdataJo = JSON.parse(JSON.stringify(authdata));
            expect(authdataJo).toEqual(dataJo);
        });
    });
    
    it("encode exception", function() {
        var exception;
        runs(function() {
	        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
	        var entityAuthJO = data.getAuthData();
	        delete entityAuthJO[KEY_IDENTITY];
            factory.createData(ctx, entityAuthJO, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("crypto context", function() {
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });

    it("unknown key ID", function() {
        var f = function() {
	        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, "x");
	        factory.getCryptoContext(ctx, data);
	    };
        expect(f).toThrow(new MslEntityAuthException(MslError.RSA_PUBLICKEY_NOT_FOUND));
    });
    
    it("local crypto context", function() {
        var rsaStore = new RsaStore();
        rsaStore.addPrivateKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PRIVKEY);
        factory = new RsaAuthenticationFactory(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, rsaStore);
        ctx.addEntityAuthenticationFactory(factory);
        
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        
        var plaintext = new Uint8Array(16);
        ctx.getRandom().nextBytes(plaintext);
        cryptoContext.sign(plaintext, {
            result: function(ciphertext) {},
            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        });
    });
    
    it("missing private key", function() {
        var f = function() {
            var rsaStore = new RsaStore();
            rsaStore.addPublicKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PUBKEY);
            var factory = new RsaAuthenticationFactory(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, rsaStore);
            
            var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.RSA_PRIVATEKEY_NOT_FOUND));
    });
});
