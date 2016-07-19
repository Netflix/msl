/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
 * ECC crypto context unit tests.
 *
 */
describe("EccCryptoContext", function() {
    var publicKeyA;
    var privateKeyA;
    var publicKeyB;
    var privateKeyB;

    var ECDSA_KEYPAIR_A = {
        publicKeyJSON: {
            "kty": "EC",
            "crv": "P-256",
            "x":   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use": "sig",
            "kid": "A"
         },
        privateKeyJSON: {
            "kty": "EC",
            "crv": "P-256",
            "x":   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d":   "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
            "use": "sig",
            "kid": "Apriv"
         }
     };

    var ECDSA_KEYPAIR_B = {
        publicKeyJSON: {
            "kty": "EC",
            "crv": "P-256",
            "x":   "10jF0O9oX8GOXxxHgC9gktZbduHn0K3XI5EDum_fOkc",
            "y":   "eBVHsIhtASlzUIzGnMAl0TDfj0pqgldZrbsZobEL-78",
            "use": "sig",
            "kid": "B"
         },
        privateKeyJSON: {
            "kty": "EC",
            "crv": "P-256",
            "x":   "10jF0O9oX8GOXxxHgC9gktZbduHn0K3XI5EDum_fOkc",
            "y":   "eBVHsIhtASlzUIzGnMAl0TDfj0pqgldZrbsZobEL-78",
            "d":   "TBP2kKufnhTHEf88VPcOIPDlk8uAFlLgi7C1iv86huY",
            "use": "sig",
            "kid": "B"
         }
     };

    /** Random. */
    var random = new Random();
    /** Message. */
    var message = new Uint8Array(32);
    random.nextBytes(message);
    /** MSL context. */
    var ctx = null;
    var initialized = false;

    beforeEach(function() {
        var extractable = true;
        var _algo = { name: "ECDSA", namedCurve: "P-256" };

        if (!initialized) {
            runs(function() {
                mslCrypto["importKey"]("jwk", ECDSA_KEYPAIR_A.publicKeyJSON, _algo, extractable, ["verify"])
                    .then(function (key) {
                        publicKeyA = key;
                    },
                    function (err) {
                        console.log(err);
                    }
                );
                mslCrypto["importKey"]("jwk", ECDSA_KEYPAIR_A.privateKeyJSON, _algo, extractable, ["sign"])
                    .then(function (key) {
                        privateKeyA = key;
                    },
                    function (err) {
                        console.log(err);
                    }
                );
                mslCrypto["importKey"]("jwk", ECDSA_KEYPAIR_B.publicKeyJSON, _algo, extractable, ["verify"])
                    .then(function (key) {
                        publicKeyB = key;
                    },
                    function (err) {
                        console.log(err);
                    }
                );
                mslCrypto["importKey"]("jwk", ECDSA_KEYPAIR_B.privateKeyJSON, _algo, extractable, ["sign"])
                    .then(function (key) {
                        privateKeyB = key;
                    },
                    function (err) {
                        console.log(err);
                    }
                );
            });
            waitsFor(function() { return publicKeyA && privateKeyA && publicKeyB && privateKeyB; }, "Import ECDSA keypairs A/B", 1500);
            initialized = true;
        }
    });

    describe("sign/verify", function() {

         var oncomplete = function(pkey) {
             return pkey;
         };

         var onerror = function(err) {
             console.log(err);
         }

        it("sign/verify", function() {
            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var messageB = new Uint8Array(32);
            random.nextBytes(messageB);

            var cryptoContext = new EccCryptoContext(ctx, privateKeyA, publicKeyA, EccCryptoContext$Mode.SIGN_VERIFY);
            var signatureA = undefined, signatureB = undefined;
            runs(function() {
                cryptoContext.sign(messageA, {
                    result: function(s) { signatureA = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.sign(messageB, {
                    result: function(s) { signatureB = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signatureA && signatureB; }, "signatures", 300);
            runs(function() {
                expect(signatureA).not.toBeNull();
                expect(signatureA.length).toBeGreaterThan(0);
                expect(signatureA).not.toEqual(messageA);
                expect(signatureB.length).toBeGreaterThan(0);
                expect(signatureB).not.toEqual(signatureA);
            });

            var verifiedAA = undefined, verifiedBB = undefined, verifiedBA;
            runs(function() {
                cryptoContext.verify(messageA, signatureA, {
                    result: function(v) { verifiedAA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                cryptoContext.verify(messageB, signatureB, {
                    result: function(v) { verifiedBB = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                cryptoContext.verify(messageB, signatureA, {
                    result: function(v) { verifiedBA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified", 300);
            runs(function() {
                expect(verifiedAA).toBeTruthy();
                expect(verifiedBB).toBeTruthy();
                expect(verifiedBA).toBeFalsy();
            });
        });

        it("sign/verify with mismatched contexts", function() {
            var cryptoContextA = new EccCryptoContext(ctx, privateKeyA, publicKeyA, EccCryptoContext$Mode.SIGN_VERIFY);
            var cryptoContextB = new EccCryptoContext(ctx, privateKeyB, publicKeyB, EccCryptoContext$Mode.SIGN_VERIFY);
            var signature;
            runs(function() {
                cryptoContextA.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);
            var verified;
            runs(function() {
                cryptoContextB.verify(message, signature, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", 300);
            runs(function() {
                expect(verified).toBeFalsy();
            });
        });

        it("sign with null private key", function() {
            var cryptoContext = new EccCryptoContext(ctx, null, publicKeyA, EccCryptoContext$Mode.SIGN_VERIFY);
            var exception;
            runs(function() {
                cryptoContext.sign(message, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 300);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
            });
        });

        it("verify with null public key", function() {
            var cryptoContext = new EccCryptoContext(ctx, privateKeyA, null, EccCryptoContext$Mode.SIGN_VERIFY);
            var signature;
            runs(function() {
                cryptoContext.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);

            var exception;
            runs(function() {
                cryptoContext.verify(message, signature, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED));
            });
        });
    });
});
