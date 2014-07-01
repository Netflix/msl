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
 * JSON Web Encryption ladder exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("JsonWebEncryptionLadderExchange", function() {
// Do nothing unless executing in the legacy Web Crypto environment.
if (mslCrypto$version == MslCrypto$WebCryptoVersion.LEGACY) {
    /** JSON key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    var KEY_KEYDATA = "keydata";
    
    // Shortcuts.
    var Algorithm = JsonWebEncryptionCryptoContext$Algorithm;
    var Encryption = JsonWebEncryptionCryptoContext$Encryption;
    var Mechanism = JsonWebEncryptionLadderExchange$Mechanism;
    var RequestData = JsonWebEncryptionLadderExchange$RequestData;
    var RequestData$parse = JsonWebEncryptionLadderExchange$RequestData$parse;
    var ResponseData = JsonWebEncryptionLadderExchange$ResponseData;
    var ResponseData$parse = JsonWebEncryptionLadderExchange$ResponseData$parse;
    
    var PSK_CRYPTO_CONTEXT, WRAP_CRYPTO_CONTEXT;
    var WRAP_JWK;
    var WRAPDATA;

    var PSK_IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    var PSK_MASTER_TOKEN;
    var PSK_ENCRYPTION_JWK;
    var PSK_HMAC_JWK;

    /** Random. */
    var random = new Random();
    /** PSK MSL context. */
    var pskCtx;
    /** Plaintext data. */
    var data = new Uint8Array(128);
    random.nextBytes(data);
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { pskCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return pskCtx; }, "pskCtx", 100);
            
            var wrapKey;
            runs(function() {
                // Create PSK wrapping crypto context.
                PSK_CRYPTO_CONTEXT = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, MockPresharedAuthenticationFactory.KPW);

                // The wrap key is the new wrapping key wrapped by the specified
                // wrapping key (e.g. PSK or RSA) inside a JWK. Technically we
                // shouldn't know this but that's the only way to verify things.
                //
                // Create the new wrapping key and wrap crypto context.
                var wrappingKey = new Uint8Array(16);
                pskCtx.getRandom().nextBytes(wrappingKey);
                CipherKey$import(wrappingKey, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(k) { wrapKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapKey; }, "wrap key", 100);

            runs(function() {
                WRAP_CRYPTO_CONTEXT = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, wrapKey);
                //
                // Wrap the new wrapping key using a PSK wrap crypto context.
                PSK_CRYPTO_CONTEXT.wrap(wrapKey, {
                    result: function(x) { WRAP_JWK = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                // The wrap data is an AES-128 key wrapped by the primary MSL
                // context. Technically we shouldn't know this but that's the only
                // way to verify things.
                pskCtx.getMslCryptoContext().wrap(wrapKey, {
                    result: function(x) { WRAPDATA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var repository = new MockCryptoContextRepository();
                var keyxFactory = new JsonWebEncryptionLadderExchange(repository);
                pskCtx.addKeyExchangeFactory(keyxFactory);

                MslTestUtils.getMasterToken(pskCtx, 1, 1, {
                    result: function(x) { PSK_MASTER_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return WRAP_JWK && WRAPDATA && PSK_MASTER_TOKEN; }, "wrapped JWK, wrap data, and PSK master token", 100);

            runs(function() {
                var pskEncryptionKey = PSK_MASTER_TOKEN.encryptionKey;
                WRAP_CRYPTO_CONTEXT.wrap(pskEncryptionKey, {
                    result: function(x) { PSK_ENCRYPTION_JWK = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                var pskHmacKey = PSK_MASTER_TOKEN.hmacKey;
                WRAP_CRYPTO_CONTEXT.wrap(pskHmacKey, {
                    result: function(x) { PSK_HMAC_JWK = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return PSK_ENCRYPTION_JWK && PSK_HMAC_JWK; }, "wrapped PSK encryption key and HMAC key", 100);
            
            runs(function() { initialized = true; });
        }
    });
    
    afterEach(function() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    });
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        /** JSON key wrap key wrapping mechanism. */
        var KEY_MECHANISM = "mechanism";
        /** JSON key public key. */
        var KEY_PUBLIC_KEY = "publickey";
        /** key wrap data. */
        var KEY_WRAPDATA = "wrapdata";
        
        xit("ctors with RSA keys", function() {
            var req = new RequestData(Mechanism.RSA, KEYPAIR_ID, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY, null);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
            expect(req.mechanism).toEqual(Mechanism.RSA);
            expect(req.privateKey.getEncoded()).toEqual(RSA_PRIVATE_KEY.getEncoded());
            expect(req.publicKey.getEncoded()).toEqual(RSA_PUBLIC_KEY.getEncoded());
            expect(req.wrapdata).toBeNull();
            expect(req.wrapKeyId).toEqual(KEYPAIR_ID);
            var keydata = req.getKeydata();
            expect(keydata).not.toBeNull();
            var joReq;
            runs(function() {
                RequestData$parse(keydata, {
                    result: function(data) { joReq = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return joReq; }, "joReq", 100);
            
            runs(function() {
                expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                expect(joReq.mechanism).toEqual(req.mechanism);
                expect(joReq.privateKey).toBeNull();
                expect(joReq.publicKey.getEncoded()).toEqual(req.publicKey.getEncoded());
                expect(joReq.wrapdata).toEqual(req.wrapdata);
                expect(joReq.wrapKeyId).toEqual(req.wrapKeyId);
                var joKeydata = req.getKeydata();
                expect(joKeydata).not.toBeNull();
                expect(joKeydata).toEqual(keydata);
            });
        });
        
        xit("json is correct with RSA keys", function() {
            var req = new RequestData(Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY, null);
            var jo = JSON.parse(JSON.stringify(req));
            expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.JWE_LADDER.name);
            var keydata = jo[KEY_KEYDATA];
            expect(keydata[KEY_MECHANISM]).toEqual(Mechanism.RSA);
            expect(base64$decode(keydata[KEY_PUBLIC_KEY])).toEqual(RSA_PUBLIC_KEY.getEncoded());
            expect(keydata[KEY_WRAPDATA]).toBeFalsy();
        });
        
        xit("create with RSA keys", function() {
            var req = new RequestData(Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY, null);
            var jo = JSON.parse(JSON.stringify(req));
            var keyRequestData;
            runs(function() {
                KeyRequestData$parse(pskCtx, jo, {
                    result: function(data) { keyRequestData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyRequestData; }, "keyRequestData", 100);
            
            runs(function() {
                expect(keyRequestData).not.toBeNull();
                expect(keyRequestData instanceof RequestData).toBeTruthy();

                var joReq = keyRequestData;
                expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                expect(joReq.mechanism).toEqual(req.mechanism);
                expect(joReq.privateKey).toBeNull();
                expect(joReq.publicKey.getEncoded()).toEqual(req.publicKey.getEncoded());
                expect(joReq.wrapdata).toEqual(req.wrapdata);
            });
        });
        
        xit("ctor with RSA keys and null public key", function() {
            var f = function() {
                new RequestData(Mechanism.RSA, null, RSA_PRIVATE_KEY, null);
            };
            expect(f).toThrow(new MslInternalException());
        });
        
        xit("ctor with RSA keys and null private key", function() {
            var f = function() {
                new RequestData(Mechanism.RSA, RSA_PUBLIC_KEY, null, null);
            };
            expect(f).toThrow(new MslInternalException());
        });
        
        it("ctors with wrapdata", function() {
            var req = new RequestData(Mechanism.WRAP, WRAPDATA);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
            expect(req.mechanism).toEqual(Mechanism.WRAP);
            expect(req.wrapdata).toEqual(WRAPDATA);
            var keydata = req.getKeydata();
            expect(keydata).not.toBeNull();
            
            var joReq = RequestData$parse(keydata);
            expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
            expect(joReq.mechanism).toEqual(req.mechanism);
            expect(joReq.wrapdata).toEqual(req.wrapdata);
            var joKeydata = req.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("json is correct with wrapdata", function() {
            var req = new RequestData(Mechanism.WRAP, WRAPDATA);
            var jo = JSON.parse(JSON.stringify(req));
            expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.JWE_LADDER.name);
            var keydata = jo[KEY_KEYDATA];
            expect(keydata[KEY_MECHANISM]).toEqual(Mechanism.WRAP);
            expect(keydata[KEY_PUBLIC_KEY]).toBeFalsy();
            expect(base64$decode(keydata[KEY_WRAPDATA])).toEqual(WRAPDATA);
        });
        
        it("create with wrapdata", function() {
            var req = new RequestData(Mechanism.WRAP, WRAPDATA);
            var jo = JSON.parse(JSON.stringify(req));
            var keyRequestData;
            runs(function() {
                KeyRequestData$parse(pskCtx, jo, {
                    result: function(data) { keyRequestData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyRequestData; }, "keyRequestData", 100);
            
            runs(function() {
                expect(keyRequestData).not.toBeNull();
                expect(keyRequestData instanceof RequestData).toBeTruthy();
                
                var joReq = keyRequestData;
                expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                expect(joReq.mechanism).toEqual(req.mechanism);
                expect(joReq.wrapdata).toEqual(req.wrapdata);
            });
        });
        
        it("ctor with wrapdata and null wrapdata", function() {
            var f = function() {
                new RequestData(Mechanism.WRAP, null);
            };
            expect(f).toThrow(new MslInternalException());
        });
        
        it("ctor with PSK", function() {
            var req = new RequestData(Mechanism.PSK, null);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
            expect(req.mechanism).toEqual(Mechanism.PSK);
            expect(req.wrapdata).toBeNull();
            var keydata = req.getKeydata();
            expect(keydata).not.toBeNull();
            
            var joReq = RequestData$parse(keydata);
            expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
            expect(joReq.mechanism).toEqual(req.mechanism);
            expect(joReq.wrapdata).toBeNull();
            var joKeydata = req.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("json is correct with PSK", function() {
            var req = new RequestData(Mechanism.PSK, null);
            var jo = JSON.parse(JSON.stringify(req));
            expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.JWE_LADDER.name);
            var keydata = jo[KEY_KEYDATA];
            expect(keydata[KEY_MECHANISM]).toEqual(Mechanism.PSK);
            expect(keydata[KEY_PUBLIC_KEY]).toBeFalsy();
            expect(keydata[KEY_WRAPDATA]).toBeFalsy();
        });
        
        it("create with PSK", function() {
            var req = new RequestData(Mechanism.PSK, null);
            var jo = JSON.parse(JSON.stringify(req));
            var keyRequestData;
            runs(function() {
                KeyRequestData$parse(pskCtx, jo, {
                    result: function(data) { keyRequestData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyRequestData; }, "keyRequestData", 100);
            
            runs(function() {
                expect(keyRequestData).not.toBeNull();
                expect(keyRequestData instanceof RequestData).toBeTruthy();
                
                var joReq = keyRequestData;
                expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                expect(joReq.mechanism).toEqual(req.mechanism);
                expect(joReq.wrapdata).toBeNull();
            });
        });
        
        it("missing mechanism", function() {
            var f = function() {
                var req = new RequestData(Mechanism.PSK, null);
                var keydata = req.getKeydata();

                expect(keydata[KEY_MECHANISM]).not.toBeNull();
                delete keydata[KEY_MECHANISM];

                RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("invalid mechanism", function() {
            var f = function() {
                var req = new RequestData(Mechanism.PSK, null);
                var keydata = req.getKeydata();

                keydata[KEY_MECHANISM] = "x";

                RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM));
        });
        
        it("wrap with missing wrapdata", function() {
            var f = function() {
                var req = new RequestData(Mechanism.WRAP, WRAPDATA);
                var keydata = req.getKeydata();

                expect(keydata[KEY_WRAPDATA]).not.toBeNull();
                delete keydata[KEY_WRAPDATA];

                RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("wrap with invalid wrapdata", function() {
            var f = function() {
                var req = new RequestData(Mechanism.WRAP, WRAPDATA);
                var keydata = req.getKeydata();

                keydata[KEY_WRAPDATA] = "x";

                RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING));
        });
        
        it("equals mechanism", function() {
            var dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            var dataB = new RequestData(Mechanism.PSK, null);
            var dataA2 = RequestData$parse(dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        }); 
        
        it("equals wrapdata", function() {
            var wrapdataB = Arrays$copyOf(WRAPDATA, 0, WRAPDATA.length);
            ++wrapdataB[0];
            
            var dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            var dataB = new RequestData(Mechanism.WRAP, wrapdataB);
            var dataA2 = RequestData$parse(dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
    });
    
    /** Response data unit tests. */
    describe("ResponseData", function() {
        /** JSON key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";
        
        /** JSON key wrapping key. */
        var KEY_WRAP_KEY = "wrapkey";
        /** JSON key wrapping key data. */
        var KEY_WRAPDATA = "wrapdata";
        /** JSON key encrypted encryption key. */
        var KEY_ENCRYPTION_KEY = "encryptionkey";
        /** JSON key encrypted HMAC key. */
        var KEY_HMAC_KEY = "hmackey";
        
        it("ctors", function() {
            var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            expect(resp.encryptionKey).toEqual(PSK_ENCRYPTION_JWK);
            expect(resp.hmacKey).toEqual(PSK_HMAC_JWK);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
            expect(resp.masterToken).toEqual(PSK_MASTER_TOKEN);
            expect(resp.wrapdata).toEqual(WRAPDATA);
            expect(resp.wrapKey).toEqual(WRAP_JWK);
            var keydata = resp.getKeydata();
            expect(keydata).not.toBeNull();
            
            var joResp = ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            expect(joResp.encryptionKey).toEqual(resp.encryptionKey);
            expect(joResp.hmacKey).toEqual(resp.hmacKey);
            expect(joResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
            expect(joResp.masterToken).toEqual(resp.masterToken);
            expect(joResp.wrapdata).toEqual(resp.wrapdata);
            expect(joResp.wrapKey).toEqual(resp.wrapKey);
            var joKeydata = joResp.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("json is correct", function() {
            var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var jo = JSON.parse(JSON.stringify(resp));
            expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.JWE_LADDER.name);
            
            var masterToken;
            runs(function() {
                MasterToken$parse(pskCtx, jo[KEY_MASTER_TOKEN], {
                    result: function(x) { masterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken; }, "master token", 100);
            
            runs(function() {
                expect(masterToken).toEqual(PSK_MASTER_TOKEN);
                var keydata = jo[KEY_KEYDATA];
                expect(base64$decode(keydata[KEY_ENCRYPTION_KEY])).toEqual(PSK_ENCRYPTION_JWK);
                expect(base64$decode(keydata[KEY_HMAC_KEY])).toEqual(PSK_HMAC_JWK);
                expect(base64$decode(keydata[KEY_WRAPDATA])).toEqual(WRAPDATA);
                expect(base64$decode(keydata[KEY_WRAP_KEY])).toEqual(WRAP_JWK);
            });
        });
        
        it("create", function() {
            var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var jo = JSON.parse(JSON.stringify(resp));
            var keyResponseData;
            runs(function() {
                KeyResponseData$parse(pskCtx, jo, {
                    result: function(data) { keyResponseData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyResponseData; }, "keyResponseData", 100);
            
            runs(function() {
                expect(keyResponseData).not.toBeNull();
                expect(keyResponseData instanceof ResponseData).toBeTruthy();
                
                var joResp = keyResponseData;
                expect(joResp.encryptionKey).toEqual(resp.encryptionKey);
                expect(joResp.hmacKey).toEqual(resp.hmacKey);
                expect(joResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
                expect(joResp.masterToken).toEqual(resp.masterToken);
                expect(joResp.wrapdata).toEqual(resp.wrapdata);
                expect(joResp.wrapKey).toEqual(resp.wrapKey);
            });
        });
        
        it("missing wrap key", function() {
            var f = function() {
                var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
                var keydata = resp.getKeydata();

                expect(keydata[KEY_WRAP_KEY]).not.toBeNull();
                delete keydata[KEY_WRAP_KEY];

                ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("missing wrapdata", function() {
            var f = function() {
                var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
                var keydata = resp.getKeydata();

                expect(keydata[KEY_WRAPDATA]).not.toBeNull();
                delete keydata[KEY_WRAPDATA];

                ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("missing encryption key", function() {
            var f = function() {
                var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
                var keydata = resp.getKeydata();

                expect(keydata[KEY_ENCRYPTION_KEY]).not.toBeNull();
                delete keydata[KEY_ENCRYPTION_KEY];

                ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("missing HMAC key", function() {
            var f = function() {
                var resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
                var keydata = resp.getKeydata();

                expect(keydata[KEY_HMAC_KEY]).not.toBeNull();
                delete keydata[KEY_HMAC_KEY];

                ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("equals wrap key", function() {
            var wrapKeyB = Arrays$copyOf(WRAP_JWK, 0, WRAP_JWK.length);
            ++wrapKeyB[0];
            
            var dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, wrapKeyB, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals wrapdata", function() {
            var wrapdataB = Arrays$copyOf(WRAPDATA, 0, WRAPDATA.length);
            ++wrapdataB[0];
            
            var dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, wrapdataB, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals encryption key", function() {
            var encryptionKeyB = Arrays$copyOf(PSK_ENCRYPTION_JWK, 0, PSK_ENCRYPTION_JWK.length);
            ++encryptionKeyB[0];
            
            var dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, encryptionKeyB, PSK_HMAC_JWK);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());

            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals HMAC key", function() {
            var hmacKeyB = Arrays$copyOf(PSK_HMAC_JWK, 0, PSK_HMAC_JWK.length);
            ++hmacKeyB[0];
            
            var dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, hmacKeyB);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
    });
    
    /** Key exchange factory unit tests. */
    describe("KeyExchangeFactory", function() {
        /**
         * Fake key request data for the JSON Web Key key ladder key exchange
         * scheme.
         */
        var FakeKeyRequestData = KeyRequestData.extend({
            /** Create a new fake key request data. */
            init: function init() {
                init.base.call(this, KeyExchangeScheme.JWE_LADDER);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            }
        });
        
        /**
         * Fake key response data for the JSON Web Key key ladder key exchange
         * scheme.
         */
        var FakeKeyResponseData = KeyResponseData.extend({
            /** Create a new fake key response data. */
            init: function init() {
                init.base.call(this, PSK_MASTER_TOKEN, KeyExchangeScheme.JWE_LADDER);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            }
        });
        
        /**
         * Unwrap a JSON Web Key and return the secret key it contains.
         * 
         * @param {ICryptoContext} wrapCryptoContext crypto context for unwrapping the JSON Web Key.
         * @param {Uint8Array} wrappedJwk the wrapped JSON Web Key.
         * @param {WebCryptoAlgorithm} algo the wrapped JSON Web Key web crypto algorithm.
         * @param {Array.<string>} usages the wrapped JSON Web Key web crypto key usages.
         * @param {result: function(CipherKey), error: function(Error)}
         *        callback the callback that will receive the secret key or any
         *        thrown exceptions.
         * @throws MslCryptoException if there is an error unwrapping the JSON
         *         Web Key.
         * @throws JSONException if there is an error reconstructing the JSON
         *         Web Key JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON
         *         Web Key JSON object.
         */
        function extractJwkSecretKey(wrapCryptoContext, wrappedJwk, algo, usages, callback) {
            wrapCryptoContext.unwrap(wrappedJwk, algo, usages, callback);
        }
        
        var KEY_ID = "keyId";
        
        /** Random. */
        var random = new Random();
        /** JWK key ladder crypto context repository. */
        var repository = new MockCryptoContextRepository();
        /** Key exchange factory. */
        var factory = new JsonWebEncryptionLadderExchange(repository);
        
        beforeEach(function() {
            pskCtx.getMslStore().clearCryptoContexts();
            pskCtx.getMslStore().clearServiceTokens();
            repository.clear();
        });
        
        it("factory", function() {
            expect(factory.scheme).toEqual(KeyExchangeScheme.JWE_LADDER);
        });
        
        it("generate initial response with wrap", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return req && keyxData; }, "req and keyxData not received", 100);
           
            // Unwrap the new wrapping key and create a crypto context from it.
            var masterToken, respdata, wrappingKey;
            runs(function() {
                expect(keyxData).not.toBeNull();
                expect(keyxData.cryptoContext).not.toBeNull();
                expect(keyxData.keyResponseData).not.toBeNull();
                
                var resp = keyxData.keyResponseData;
                expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
                masterToken = resp.masterToken;
                expect(masterToken).not.toBeNull();
                expect(masterToken.identity).toEqual(PSK_IDENTITY);
                
                expect(resp instanceof ResponseData).toBeTruthy();
                
                respdata = resp;
                extractJwkSecretKey(WRAP_CRYPTO_CONTEXT, respdata.wrapKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                    result: function(k) { wrappingKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken && respdata && wrappingKey; }, "masterToken and repdata and wrappingKey", 100);

            var encryptionKey, hmacKey;
            runs(function() {
                var wrapCryptoContext = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, wrappingKey);
            
                // Unwrap the session keys.
                extractJwkSecretKey(wrapCryptoContext, respdata.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, {
                    result: function(k) { encryptionKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                extractJwkSecretKey(wrapCryptoContext, respdata.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoAlgorithm.SIGN_VERIFY, {
                    result: function(k) { hmacKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encryptionKey && hmacKey; }, "encryptionKey and hmacKey", 100);
            
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refCryptoContext, wrapCryptoContext, refCiphertext, wrapCiphertext, refHmac, wrapHmac;
            runs(function() {
                refCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, masterToken.encryptionKey, masterToken.hmacKey, null);
                wrapCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, encryptionKey, hmacKey, null);
                refCryptoContext.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext && refHmac && wrapHmac; }, "ciphertexts and HMACs", 100);
            var refPlaintext, wrapPlaintext, refVerified, wrapVerified;
            runs(function() {
                refCryptoContext.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.verify(data, wrapHmac, {
                    result: function(x) { refVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.verify(data, refHmac, {
                    result: function(x) { wrapVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts and verifieds", 100);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
                expect(refVerified).toBeTruthy();
                expect(wrapVerified).toBeTruthy();
            });
        });
        
        // FIXME: Disabled without access to PSK key handle.
        xit("generate initial response with PSK", function() {
            var keyxData;
            runs(function() {
                var req = new RequestData(Mechanism.PSK, null);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
           
            var masterToken, respdata, wrappingKey;
            runs(function() {
                expect(keyxData).not.toBeNull();
                expect(keyxData.cryptoContext).not.toBeNull();
                expect(keyxData.keyResponseData).not.toBeNull();
                
                var resp = keyxData.keyResponseData;
                expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
                masterToken = resp.masterToken;
                expect(masterToken).not.toBeNull();
                expect(masterToken.identity).toEqual(PSK_IDENTITY);
                
                // Unwrap the new wrapping key and create a crypto context from it.
                expect(resp instanceof ResponseData).toBeTruthy();
                var respdata = resp;
                extractJwkSecretKey(PSK_CRYPTO_CONTEXT, respdata.wrapKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                   result: function(k) { wrappingKey = k; },
                   error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken && respdata && wrappingKey; }, "masterToken and respdata and wrappingKey", 100);

            var encryptionKey, hmacKey;
            runs(function() {
                var wrapCryptoContext = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, wrappingKey);
            
                // Unwrap the session keys.
                extractJwkSecretKey(wrapCryptoContext, respdata.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, {
                    result: function(k) { encryptionKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                extractJwkSecretKey(wrapCryptoContext, respdata.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoAlgorithm.SIGN_VERIFY, {
                    result: function(k) { hmacKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encryptionKey && hmacKey; }, "encryptionKey and hmacKey", 100);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refCryptoContext, wrapCryptoContext, refCiphertext, wrapCiphertext, refHmac, wrapHmac;
            runs(function() {
                refCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, masterToken.encryptionKey, masterToken.hmacKey, null);
                wrapCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, encryptionKey, hmacKey, null);
                refCryptoContext.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext && refHmac && wrapHmac; }, "ciphertexts and HMACs", 100);
            var refPlaintext, wrapPlaintext, refVerified, wrapVerified;
            runs(function() {
                refCryptoContext.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.verify(data, wrapHmac, {
                    result: function(x) { refVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.verify(data, refHmac, {
                    result: function(x) { wrapVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts and verifieds", 100);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
                expect(refVerified).toBeTruthy();
                expect(wrapVerified).toBeTruthy();
            });
        });
        
        it("generate initial response with wrong request", function() {
            var exception;
            runs(function() {
                var req = new FakeKeyRequestData();
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response with wrap", function() {
            var keyxData;
            runs(function() {
                var req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var masterToken, respdata, wrappingKey;
            runs(function() {
                expect(keyxData).not.toBeNull();
                expect(keyxData.cryptoContext).not.toBeNull();
                expect(keyxData.keyResponseData).not.toBeNull();

                var resp = keyxData.keyResponseData;
                expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
                masterToken = resp.masterToken;
                expect(masterToken).not.toBeNull();
                expect(masterToken.identity).toEqual(PSK_MASTER_TOKEN.identity);
                expect(masterToken.serialNumber).toEqual(PSK_MASTER_TOKEN.serialNumber);
                expect(masterToken.sequenceNumber).toEqual(PSK_MASTER_TOKEN.sequenceNumber + 1);

                // Unwrap the new wrapping key and create a crypto context from it.
                expect(resp instanceof ResponseData).toBeTruthy();
                respdata = resp;
                extractJwkSecretKey(WRAP_CRYPTO_CONTEXT, respdata.wrapKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                    result: function(k) { wrappingKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken && respdata && wrappingKey; }, "masterToken and respdata and wrappingKey", 100);

            var encryptionKey, hmacKey;
            runs(function() {
                var wrapCryptoContext = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, wrappingKey);
            
                // Unwrap the session keys.
                extractJwkSecretKey(wrapCryptoContext, respdata.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, {
                    result: function(k) { encryptionKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                extractJwkSecretKey(wrapCryptoContext, respdata.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoAlgorithm.SIGN_VERIFY, {
                    result: function(k) { hmacKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encryptionKey && hmacKey; }, "encryptionKey and hmacKey", 100);
            
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refCryptoContext, wrapCryptoContext, refCiphertext, wrapCiphertext, refHmac, wrapHmac;
            runs(function() {
                refCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, masterToken.encryptionKey, masterToken.hmacKey, null);
                wrapCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, encryptionKey, hmacKey, null);
                refCryptoContext.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext && refHmac && wrapHmac; }, "ciphertexts and HMACs", 100);
            var refPlaintext, wrapPlaintext, refVerified, wrapVerified;
            runs(function() {
                refCryptoContext.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.verify(data, wrapHmac, {
                    result: function(x) { refVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.verify(data, refHmac, {
                    result: function(x) { wrapVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts and verifieds", 100);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
                expect(refVerified).toBeTruthy();
                expect(wrapVerified).toBeTruthy();
            });
        });

        // FIXME: Disabled without access to PSK key handle.
        xit("generate subequent response with PSK", function() {
            var keyxData;
            runs(function() {
                var req = new RequestData(Mechanism.PSK, null);
                factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var masterToken, respdata, wrappingKey;
            runs(function() {
                expect(keyxData).not.toBeNull();
                expect(keyxData.cryptoContext).not.toBeNull();
                expect(keyxData.keyResponseData).not.toBeNull();

                var resp = keyxData.keyResponseData;
                expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.JWE_LADDER);
                masterToken = resp.masterToken;
                expect(masterToken).not.toBeNull();
                expect(masterToken.identity).toEqual(PSK_MASTER_TOKEN.identity);
                expect(masterToken.serialNumber).toEqual(PSK_MASTER_TOKEN.serialNumber);
                expect(masterToken.sequenceNumber).toEqual(PSK_MASTER_TOKEN.sequenceNumber + 1);

                // Unwrap the new wrapping key and create a crypto context from it.
                expect(resp instanceof ResponseData).toBeTruthy();
                respdata = resp;
                extractJwkSecretKey(PSK_CRYPTO_CONTEXT, respdata.wrapKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                    result: function(k) { wrappingKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken && respdata && wrappingKey; }, "masterToken and respdata and wrappingKey", 100);

            var encryptionKey, hmacKey;
            runs(function() {
                var wrapCryptoContext = new JsonWebEncryptionCryptoContext(pskCtx, Algorithm.A128KW, Encryption.A128GCM, wrappingKey);

                // Unwrap the session keys.
                extractJwkSecretKey(wrapCryptoContext, respdata.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, {
                    result: function(k) { encryptionKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                extractJwkSecretKey(wrapCryptoContext, respdata.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoAlgorithm.SIGN_VERIFY, {
                    result: function(k) { encryptionKey = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encryptionKey && hmacKey; }, "encryptionKey and hmacKey", 100);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refCryptoContext, wrapCryptoContext, refCiphertext, wrapCiphertext, refHmac, wrapHmac;
            runs(function() {
                refCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, masterToken.encryptionKey, masterToken.hmacKey, null);
                wrapCryptoContext = new SymmetricCryptoContext(pskCtx, KEY_ID, encryptionKey, hmacKey, null);
                refCryptoContext.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext && refHmac && wrapHmac; }, "ciphertexts and HMACs", 100);
            var refPlaintext, wrapPlaintext, refVerified, wrapVerified;
            runs(function() {
                refCryptoContext.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                refCryptoContext.verify(data, wrapHmac, {
                    result: function(x) { refVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.verify(data, refHmac, {
                    result: function(x) { wrapVerified = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts and verifieds", 100);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
                expect(refVerified).toBeTruthy();
                expect(wrapVerified).toBeTruthy();
            });
        });
        
        it("generate subsequent response with wrong request", function() {
            var exception;
            runs(function() {
                var req = new FakeKeyRequestData();
                factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response with untrusted master token", function() {
            var masterToken;
            runs(function() {
                MslTestUtils.getUntrustedMasterToken(pskCtx, {
                    result: function(t) { masterToken = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken; }, "masterToken", 100);
            
            var exception;
            runs(function() {
                var req = new RequestData(Mechanism.PSK, null);
                factory.generateResponse(pskCtx, req, masterToken, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
            });
        });
        
        it("get crypto context with wrap", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var reqCryptoContext, resp, respCryptoContext;
            runs(function() {
                reqCryptoContext = keyxData.cryptoContext;
                resp = keyxData.keyResponseData;

                // We must put the wrapping key into the repository to create the
                // response crypto context.
                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                expect(repository.getCryptoContext(WRAPDATA)).not.toBeNull();
                factory.getCryptoContext(pskCtx, req, resp, null, {
                    result: function(x) { respCryptoContext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return reqCryptoContext && respCryptoContext; }, "crypto contexts", 100);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext, responseCiphertext;
            runs(function() {
                var wrapdata = repository.getWrapdata();
                expect(wrapdata).not.toBeNull();
                expect(wrapdata).not.toEqual(WRAPDATA);
                expect(wrapdata).toEqual(resp.wrapdata);
                
                reqCryptoContext.encrypt(data, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.encrypt(data, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts", 100);
            
            // Signatures should always be equal.
            var requestSignature, responseSignature;
            runs(function() {
                expect(requestCiphertext).not.toEqual(data);
                expect(responseCiphertext).not.toEqual(data);

                reqCryptoContext.sign(data, {
                    result: function(data) { requestSignature = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.sign(data, {
                    result: function(data) { responseSignature = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures", 100);
            
            // Plaintext should always be equal to the original message.
            var requestPlaintext, responsePlaintext;
            runs(function() {
                expect(requestSignature).not.toEqual(data);
                expect(responseSignature).not.toEqual(data);
                expect(responseSignature).toEqual(requestSignature);
                
                reqCryptoContext.decrypt(responseCiphertext, {
                    result: function(data) { requestPlaintext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.decrypt(requestCiphertext, {
                    result: function(data) { responsePlaintext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts", 100);
            
            // Verification should always succeed.
            var reqVerified, respVerified;
            runs(function() {
                expect(requestPlaintext).not.toBeNull();
                expect(requestPlaintext).toEqual(data);
                expect(responsePlaintext).toEqual(requestPlaintext);
                
                reqCryptoContext.verify(data, responseSignature, {
                    result: function(verified) { reqVerified = verified; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.verify(data, requestSignature, {
                    result: function(verified) { respVerified = verified; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return reqVerified && respVerified; }, "verifieds", 100);
            
            runs(function() {
                expect(reqVerified).toBeTruthy();
                expect(respVerified).toBeTruthy();
            });
        });

        // FIXME: Disabled without access to PSK key handle.
        xit("get crypto context with PSK", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.PSK, null);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var reqCryptoContext, respCryptoContext;
            runs(function() {
                reqCryptoContext = keyxData.cryptoContext;
                var resp = keyxData.keyResponseData;
            
                expect(repository.getWrapdata()).toBeNull();
            
                factory.getCryptoContext(pskCtx, req, resp, null, {
                    result: function(x) { respCryptoContext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return reqCryptoContext && respCryptoContext; }, "crypto contexts", 100);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext, responseCiphertext;
            runs(function() {
                expect(repository.getWrapdata()).toEqual(resp.wrapdata);
                
                reqCryptoContext.encrypt(data, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.encrypt(data, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts", 100);
            
            // Signatures should always be equal.
            var requestSignature, responseSignature;
            runs(function() {
                expect(requestCiphertext).not.toEqual(data);
                expect(responseCiphertext).not.toEqual(data);

                reqCryptoContext.sign(data, {
                    result: function(data) { requestSignature = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.sign(data, {
                    result: function(data) { responseSignature = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures", 100);
            
            // Plaintext should always be equal to the original message.
            var requestPlaintext, responsePlaintext;
            runs(function() {
                expect(requestSignature).not.toEqual(data);
                expect(responseSignature).not.toEqual(data);
                expect(responseSignature).toEqual(requestSignature);
                
                reqCryptoContext.decrypt(responseCiphertext, {
                    result: function(data) { requestPlaintext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.decrypt(requestCiphertext, {
                    result: function(data) { responsePlaintext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts", 100);
            
            // Verification should always succeed.
            var requestVerified, responseVerified;
            runs(function() {
                expect(requestPlaintext).not.toBeNull();
                expect(requestPlaintext).toEqual(data);
                expect(responsePlaintext).toEqual(requestPlaintext);
                
                reqCryptoContext.verify(data, responseSignature, {
                    result: function(verified) { requestVerified = true; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                respCryptoContext.verify(data, requestSignature, {
                    result: function(verified) { responseVerified = true; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestVerified && responseVerified; }, "verifieds", 100);
        
            runs(function() {
                expect(requestVerified).toBeTruthy();
                expect(responseVerified).toBeTruthy();
            });
        });
        
        it("get crypto context with wrong request", function() {
            var keyxData;
            runs(function() {
                var req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var exception;
            runs(function() {
                var resp = keyxData.keyResponseData;
                
                var fakeReq = new FakeKeyRequestData();
                factory.getCryptoContext(pskCtx, fakeReq, resp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("get crypto context with wrong response", function() {
            var exception;
            runs(function() {
                var req = new RequestData(Mechanism.PSK, null);
                var fakeResp = new FakeKeyResponseData();
                factory.getCryptoContext(pskCtx, req, fakeResp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        // FIXME: Disabled without access to PSK key handle.
        xit("get crypto context with PSK as unsupported", function() {
            var ctx;
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);

            var keyxData;
            runs(function() {
                var req = new RequestData(Mechanism.PSK, null);
                factory.generateResponse(ctx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var exception;
            runs(function() {
                var resp = keyxData.keyResponseData;

                ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                factory.getCryptoContext(ctx, req, resp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM));
            });
        });
        
        it("get crypto context with wrap key missing", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);

            var exception;
            runs(function() {
                var resp = keyxData.keyResponseData;
                
                factory.getCryptoContext(pskCtx, req, resp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING));
            });
        });
        
        it("get crypto context with invalid wrap key", function() {
            var exception;
            runs(function() {
                var wrapJwk = new Uint8Array(16);
                random.nextBytes(wrapJwk);
                
                var req = new RequestData(Mechanism.WRAP, WRAPDATA);
                var invalidResp = new ResponseData(PSK_MASTER_TOKEN, wrapJwk, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);

                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                factory.getCryptoContext(pskCtx, req, invalidResp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });
        
        it("get crypto context with invalid encryption key", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var resp, installed;
            runs(function() {
                resp = keyxData.keyResponseData;

                // First get the new crypto context. This installs the returned
                // wrapping key in the repository.
                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                expect(repository.getWrapdata()).toEqual(WRAPDATA);
                factory.getCryptoContext(pskCtx, req, resp, null, {
                    result: function(c) { installed = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return resp && installed; }, "response installed", 100);
            
            var exception;
            runs(function() {
                expect(repository.getWrapdata()).not.toEqual(WRAPDATA);
                
                // Extract values from the response.
                var masterToken = resp.masterToken;
                var wrapJwk = resp.wrapKey;
                var wrapdata = resp.wrapdata;
                var hmacJwk = resp.hmacKey;

                // Now make the invalid response.
                var encryptionJwk = new Uint8Array(16);
                random.nextBytes(encryptionJwk);
                var invalidResp = new ResponseData(masterToken, wrapJwk, wrapdata, encryptionJwk, hmacJwk);
                
                // Reinstall the previous wrap crypto context.
                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                expect(repository.getWrapdata()).toEqual(WRAPDATA);
                factory.getCryptoContext(pskCtx, req, invalidResp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });
        
        it("get crypto context with invalid HMAC key", function() {
            var req, keyxData;
            runs(function() {
                req = new RequestData(Mechanism.WRAP, WRAPDATA);
                factory.generateResponse(pskCtx, req, PSK_IDENTITY, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);

            var resp, installed;
            runs(function() {
                resp = keyxData.keyResponseData;
                
                // First get the new crypto context. This installs the returned
                // wrapping key in the repository.
                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                expect(repository.getWrapdata()).toEqual(WRAPDATA);
                factory.getCryptoContext(pskCtx, req, resp, null, {
                    result: function(c) { installed = c; },
                    error:  function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return resp && installed; }, "response installed", 100);
            
            var exception;
            runs(function() {
                expect(repository.getWrapdata()).not.toEqual(WRAPDATA);
                
                // Extract values from the response.
                var masterToken = resp.masterToken;
                var wrapJwk = resp.wrapKey;
                var wrapdata = resp.wrapdata;
                var encryptionJwk = resp.encryptionKey;

                // Now make the invalid response.
                var hmacJwk = new Uint8Array(16);
                random.nextBytes(hmacJwk);
                var invalidResp = new ResponseData(masterToken, wrapJwk, wrapdata, encryptionJwk, hmacJwk);
                
                // Reinstall the previous wrap crypto context.
                repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
                expect(repository.getWrapdata()).toEqual(WRAPDATA);
                factory.getCryptoContext(pskCtx, req, invalidResp, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 100);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });
    });
}
});
