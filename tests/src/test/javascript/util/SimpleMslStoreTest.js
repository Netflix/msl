/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
 * Simple MSL store unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SimpleMslStore", function() {
    var SimpleMslStore = require('msl-core/util/SimpleMslStore.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var NullCryptoContext = require('msl-core/crypto/NullCryptoContext.js');
    var SessionCryptoContext = require('msl-core/crypto/SessionCryptoContext.js');
    var Random = require('msl-core/util/Random.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');

    /**
     * @param {Array.<ServiceToken>} tokensA first set of service tokens.
     * @param {Array.<ServiceToken>} tokensB second set of service tokens.
     * @return {boolean} true if the two sets contain the same service tokens.
     */
    function serviceTokensEqual(tokensA, tokensB) {
        // Compare lengths.
        if (tokensA.length != tokensB.length)
            return false;

        // Convert arrays to maps.
        var tokensMapA = {};
        tokensA.forEach(function(token) {
            tokensMapA[token.uniqueKey()] = token;
        }, this);
        var tokensMapB = {};
        tokensB.forEach(function(token) {
            tokensMapB[token.uniqueKey()] = token;
        }, this);

        // Now compare the map values using the service token equals() method.
        for (var key in tokensMapA) {
            var tokenA = tokensMapA[key];
            var tokenB = tokensMapB[key];
            if (!tokenA || !tokenB || !tokenA.equals(tokenB))
                return false;
        }
        return true;
    }

    /**
     * @param {Array.<ServiceToken>} tokensA set of service tokens to check.
     * @param {Array.<ServiceToken>} tokensB set of service tokens to look for.
     * @return {boolean} true if any token being looked for is found in the set
     *         of tokens being checked.
     */
    function serviceTokensContainsAny(tokensA, tokensB) {
        // Convert arrays to maps.
        var tokensMapA = {};
        tokensA.forEach(function(token) {
            tokensMapA[token.uniqueKey()] = token;
        }, this);
        var tokensMapB = {};
        tokensB.forEach(function(token) {
            tokensMapB[token.uniqueKey()] = token;
        }, this);

        // Look for any token B inside the set of token A.
        for (var key in tokensMapB) {
            var tokenA = tokensMapA[key];
            var tokenB = tokensMapB[key];
            if (tokenA && tokenA.equals(tokenB))
                return true;
        }
        return false;
    }

    var KEYSET_ID = "keyset";
    var USER_ID = "userid";

    /** Maximum number of randomly generated tokens. */
    var MAX_TOKENS = 3;

    /** MSL context. */
    var ctx;
    /** MSL store. */
    var store = new SimpleMslStore();

    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
        }
    });

    afterEach(function() {
        store = new SimpleMslStore();
    });

    it("store crypto context", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(store.getCryptoContext(masterToken)).toBeUndefined();

            var cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.encryptionKey, masterToken.signatureKey, null);
            store.setCryptoContext(masterToken, cc1);
            var cc2 = store.getCryptoContext(masterToken);
            expect(cc2).not.toBeNull();
            expect(cc2).toEqual(cc1);
            expect(store.getMasterToken().equals(masterToken)).toBeTruthy();
        });
    });

    it("replace crypto context", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.encryptionKey, masterToken.signatureKey, null);
            var cc2 = new NullCryptoContext();

            store.setCryptoContext(masterToken, cc1);
            var cc3 = store.getCryptoContext(masterToken);
            expect(cc3).toEqual(cc1);
            expect(cc3).not.toEqual(cc2);

            store.setCryptoContext(masterToken, cc2);
            var cc4 = store.getCryptoContext(masterToken);
            expect(cc4).not.toEqual(cc1);
            expect(cc4).toEqual(cc2);
            expect(store.getMasterToken().equals(masterToken)).toBeTruthy();
        });
    });

    it("remove crypto context", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.removeCryptoContext(masterToken);
            expect(store.getMasterToken()).toBeNull();
            expect(store.getCryptoContext(masterToken)).toBeUndefined();
        });
    });

    it("clear crypto contexts", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.encryptionKey, masterToken.signatureKey, null);
            store.setCryptoContext(masterToken, cc1);
            store.clearCryptoContexts();
            expect(store.getCryptoContext(masterToken)).toBeUndefined();
            expect(store.getMasterToken()).toBeNull();
        });
    });

    it("store two crypto contexts", function() {
        var mtA, mtB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { mtA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { mtB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mtA && mtB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var ccMtA1 = new SessionCryptoContext(ctx, mtA);
            var ccMtB1 = new SessionCryptoContext(ctx, mtB);
            store.setCryptoContext(mtA, ccMtA1);
            store.setCryptoContext(mtB, ccMtB1);

            var ccMtA2 = store.getCryptoContext(mtA);
            expect(ccMtA2).not.toBeNull();
            expect(ccMtA2).toEqual(ccMtA1);

            var ccMtB2 = store.getCryptoContext(mtB);
            expect(ccMtB2).not.toBeNull();
            expect(ccMtB2).toEqual(ccMtB1);

            expect(store.getMasterToken().equals(mtB)).toBeTruthy();
        });
    });

    it("replace two crypto contexts", function() {
        var mtA, mtB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { mtA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { mtB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mtA && mtB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var ccMtA1 = new SessionCryptoContext(ctx, mtA);
            var ccMtB1 = new SessionCryptoContext(ctx, mtB);
            store.setCryptoContext(mtA, ccMtA1);
            store.setCryptoContext(mtB, ccMtB1);
            expect(store.getMasterToken()).toEqual(mtB);

            var ccNull = new NullCryptoContext();
            store.setCryptoContext(mtA, ccNull);

            var ccMtA2 = store.getCryptoContext(mtA);
            expect(ccMtA2).not.toBeNull();
            expect(ccMtA2).not.toEqual(ccMtA1);
            expect(ccMtA2).toEqual(ccNull);

            var ccMtB2 = store.getCryptoContext(mtB);
            expect(ccMtB2).not.toBeNull();
            expect(ccMtB2).toEqual(ccMtB1);

            expect(store.getMasterToken()).toEqual(mtB);
        });
    });

    it("clear two crypto contexts", function() {
        var mtA, mtB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { mtA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { mtB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mtA && mtB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var ccMtA1 = new SessionCryptoContext(ctx, mtA);
            var ccMtB1 = new SessionCryptoContext(ctx, mtB);
            store.setCryptoContext(mtA, ccMtA1);
            store.setCryptoContext(mtB, ccMtB1);

            store.clearCryptoContexts();
            expect(store.getCryptoContext(mtA)).toBeUndefined();
            expect(store.getCryptoContext(mtA)).toBeUndefined();
            expect(store.getMasterToken()).toBeNull();
        });
    });

    it("remove two crypto contexts", function() {
        var mtA, mtB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { mtA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { mtB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mtA && mtB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var ccMtA1 = new SessionCryptoContext(ctx, mtA);
            var ccMtB1 = new SessionCryptoContext(ctx, mtB);
            store.setCryptoContext(mtA, ccMtA1);
            store.setCryptoContext(mtB, ccMtB1);

            store.removeCryptoContext(mtA);
            expect(store.getCryptoContext(mtA)).toBeUndefined();
            expect(store.getCryptoContext(mtB)).toEqual(ccMtB1);
        });
    });

    /**
     * Crypto context add/remove stress test operation.
     * 
     * Randomly adds or removes a crypto context for one of many master tokens
     * (by master token entity identity). Also iterates through the set crypto
     * contexts.
     * 
     * @param ctx MSL context.
     * @param store MSL store.
     * @param count the number of master token identities to stress.
     * @param callback
     */
    function cryptoContextStressor(ctx, store, count, callback) {
        var r = new Random();
        for (var i = 0; i < count; ++i) {
            var tokenIndex = r.nextInt(count);
            MslTestUtils.getMasterToken(ctx, tokenIndex, 1, {
                result: function(masterToken) {
                    var option = r.nextInt(4);
                    switch (option) {
                        case 0:
                            store.setCryptoContext(masterToken, null);
                            break;
                        case 1:
                            var cryptoContext = new SessionCryptoContext(ctx, masterToken);
                            store.setCryptoContext(masterToken, cryptoContext);
                            break;
                        case 2:
                            store.getCryptoContext(masterToken);
                            break;
                        case 3:
                            store.removeCryptoContext(masterToken);
                            break;
                    }
                    callback.add(1);
                },
                error: function(err) { callback.error(new MslInternalException("Unexpected master token stress test exception.", err)); }
            });
        }
    }

    it("crypto context stress test", function() {
        var ops = 0;
        runs(function() {
            for (var i = 0; i < 10 * MAX_TOKENS; ++i) {
                cryptoContextStressor(ctx, store, MAX_TOKENS, {
                    add: function(r) { ops += r; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
        });
        waitsFor(function() { return ops == 10 * MAX_TOKENS * MAX_TOKENS; }, "crypto context stress test to complete", 5000);
    });

    it("add user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);

            expect(store.getUserIdToken(USER_ID).equals(userIdToken)).toBeTruthy();
            expect(store.getUserIdToken(USER_ID + "x")).toBeUndefined();
        });
    });

    it("remove user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);

            store.removeUserIdToken(userIdToken);
            expect(store.getUserIdToken(USER_ID)).toBeUndefined();
        });
    });

    it("replace user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdTokenA);
            store.addUserIdToken(USER_ID, userIdTokenB);
            expect(store.getUserIdToken(USER_ID).equals(userIdTokenB)).toBeTruthy();
        });
    });

    it("store two user ID tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var cryptoContext = new NullCryptoContext();
            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);

            expect(store.getUserIdToken(userIdA).equals(userIdTokenA)).toBeTruthy();
            expect(store.getUserIdToken(userIdB).equals(userIdTokenB)).toBeTruthy();
        });
    });

    it("replace two user ID tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB, userIdTokenC;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 3, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB && userIdTokenC; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);

            store.addUserIdToken(userIdA, userIdTokenC);
            expect(store.getUserIdToken(userIdA).equals(userIdTokenC)).toBeTruthy();
            expect(store.getUserIdToken(userIdB).equals(userIdTokenB)).toBeTruthy();
        });
    });

    it("remove two user ID tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);

            store.removeUserIdToken(userIdTokenA);
            expect(store.getUserIdToken(userIdA)).toBeUndefined();
            expect(store.getUserIdToken(userIdB).equals(userIdTokenB)).toBeTruthy();
        });
    });

    it("clear user ID tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);

            store.clearUserIdTokens();
            expect(store.getUserIdToken(userIdA)).toBeUndefined();
            expect(store.getUserIdToken(userIdB)).toBeUndefined();
        });
    });

    it("add user ID token with unknown master token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() {
                store.addUserIdToken(USER_ID, userIdToken);
            };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NOT_FOUND));
        });
    });

    it("removing old master token does not remove user ID tokens", function() {
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB, userIdTokenC;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB && userIdTokenC; }, "user tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var userIdC = USER_ID + "C";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addUserIdToken(userIdC, userIdTokenC);

            // We still have a master token with serial number 1 so no user ID
            // tokens should be deleted.
            store.removeCryptoContext(masterTokenA);
            expect(store.getUserIdToken(userIdA).equals(userIdTokenA)).toBeTruthy();
            expect(store.getUserIdToken(userIdB).equals(userIdTokenB)).toBeTruthy();
            expect(store.getUserIdToken(userIdC).equals(userIdTokenC)).toBeTruthy();
        });
    });

    it("removing final master token removes correct user ID tokens", function() {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB, userIdTokenC;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB && userIdTokenC; }, "user tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";
            var userIdC = USER_ID + "C";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdC, userIdTokenC);

            // All of master token A's user ID tokens should be deleted.
            store.removeCryptoContext(masterTokenA);
            expect(store.getUserIdToken(userIdA)).toBeUndefined();
            expect(store.getUserIdToken(userIdB)).toBeUndefined();
            expect(store.getUserIdToken(userIdC).equals(userIdTokenC)).toBeTruthy();
        });
    });

    it("clear crypto contexts clears user ID tokens", function() {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);

            // All user ID tokens should be deleted.
            store.clearCryptoContexts();
            expect(store.getUserIdToken(userIdA)).toBeUndefined();
            expect(store.getUserIdToken(userIdB)).toBeUndefined();
        });
    });

    /**
     * User ID token add/remove stress test runner.
     * 
     * Randomly adds or removes user ID tokens. Also iterates through the user
     * ID tokens.
     * 
     * @param ctx MSL context.
     * @param store MSL store.
     * @param count the number of master token and user ID tokens to create
     *        combinations of.
     * @param callback
     */
    function userIdTokenStressor(ctx, store, count, callback) {
        var r = new Random();
        for (var i = 0; i < count; ++i) {
            var tokenIndex = r.nextInt(count);
            MslTestUtils.getMasterToken(ctx, tokenIndex, 1, {
                result: function(masterToken) {
                    var userId = r.nextInt(count);
                    MslTestUtils.getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory.USER, {
                        result: function(userIdToken) {
                            var option = r.nextInt(3);
                            switch (option) {
                                case 0:
                                    store.setCryptoContext(masterToken, new NullCryptoContext());
                                    store.addUserIdToken(USER_ID + userId, userIdToken);
                                    break;
                                case 1:
                                    store.getUserIdToken(USER_ID + userId);
                                    break;
                                case 2:
                                    store.removeUserIdToken(userIdToken);
                                    break;
                            }
                            callback.add(1);
                        },
                        error: function(err) { callback.error(new MslInternalException("Unexpected user ID token stressor exception.", err)); }
                    });
                },
                error: function(err) { callback.error(new MslInternalException("Unexpected user ID token stressor exception.", err)); }
            });
        }
    }

    it("user ID token stress test", function() {
        var ops = 0;
        runs(function() {
            for (var i = 0; i < 5 * MAX_TOKENS; ++i) {
                userIdTokenStressor(ctx, store, MAX_TOKENS, {
                    add: function(r) { ops += r; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
        });
        waitsFor(function() { return ops == 5 * MAX_TOKENS * MAX_TOKENS; }, "user ID token stress test to complete", 5000);
    });

    it("store master bound service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var tokens;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, masterToken, null, {
                result: function(tks) { tokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokens; }, "tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            store.setCryptoContext(masterToken, cryptoContext);

            var emptyTokens = store.getServiceTokens(masterToken, null);
            expect(emptyTokens).not.toBeNull();
            expect(emptyTokens.length).toEqual(0);

            store.addServiceTokens(tokens);
            var storedTokens = store.getServiceTokens(masterToken, null);
            expect(storedTokens).not.toBeNull();
            expect(serviceTokensEqual(tokens, storedTokens)).toBeTruthy();
        });
    });

    it("store master bound service tokens with unknown master token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var tokens;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, masterToken, null, {
                result: function(tks) { tokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokens; }, "tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() {
                store.addServiceTokens(tokens);
            };
            expect(f).toThrow(new MslException(MslError.NONE));

            var emptyTokens = store.getServiceTokens(masterToken, null);
            expect(emptyTokens).not.toBeNull();
            expect(emptyTokens.length).toEqual(0);
        });
    });

    it("store user bound service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var tokens;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { tokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokens; }, "tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);

            var emptyTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(emptyTokens).not.toBeNull();
            expect(emptyTokens.length).toEqual(0);

            store.addServiceTokens(tokens);
            var storedTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(storedTokens).not.toBeNull();
            expect(serviceTokensEqual(tokens, storedTokens)).toBeTruthy();
        });
    });

    it("store user bound service tokens with unknown user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var tokens;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { tokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokens; }, "tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            store.setCryptoContext(masterToken, cryptoContext);

            var f = function() {
                store.addServiceTokens(tokens);
            };
            expect(f).toThrow(new MslException(MslError.NONE));

            var emptyTokens = store.getServiceTokens(masterToken, null);
            expect(emptyTokens).not.toBeNull();
            expect(emptyTokens.length).toEqual(0);
        });
    });

    it("store unbound service tokens", function() {
        var tokens;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { tokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokens; }, "tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var emptyTokens = store.getServiceTokens(null, null);
            expect(emptyTokens).not.toBeNull();
            expect(emptyTokens.length).toEqual(0);

            store.addServiceTokens(tokens);
            var storedTokens = store.getServiceTokens(null, null);
            expect(storedTokens).not.toBeNull();
            expect(serviceTokensEqual(tokens, storedTokens)).toBeTruthy();
        });
    });

    it("remove master bound service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var masterBoundTokens, userBoundTokens, unboundTokens;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { userBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundTokens && userBoundTokens && unboundTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);
            store.addServiceTokens(masterBoundTokens);
            store.addServiceTokens(userBoundTokens);
            store.addServiceTokens(unboundTokens);

            store.removeServiceTokens(null, masterToken, null);

            // This should only return the unbound tokens.
            var storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
            expect(storedMasterBoundTokens).not.toBeNull();
            expect(serviceTokensEqual(unboundTokens, storedMasterBoundTokens)).toBeTruthy();

            // This should only return the unbound and user-bound tokens.
            var unboundAndUserBoundTokens = [];
            unboundAndUserBoundTokens.push.apply(unboundAndUserBoundTokens, unboundTokens);
            unboundAndUserBoundTokens.push.apply(unboundAndUserBoundTokens, userBoundTokens);
            var storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(serviceTokensEqual(unboundAndUserBoundTokens, storedUserBoundTokens)).toBeTruthy();

            // This should only return the unbound tokens.
            var storedUnboundTokens = store.getServiceTokens(null, null);
            expect(storedUnboundTokens).not.toBeNull();
            expect(serviceTokensEqual(unboundTokens, storedUnboundTokens)).toBeTruthy();
        });
    });

    it("remove service tokens by master token and user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var masterBoundTokens, userBoundTokens, unboundTokens;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { userBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundTokens && userBoundTokens && unboundTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);
            store.addServiceTokens(masterBoundTokens);
            store.addServiceTokens(userBoundTokens);
            store.addServiceTokens(unboundTokens);

            store.removeServiceTokens(null, null, userIdToken);

            // This should only return the unbound and master bound-only tokens.
            var storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
            expect(storedMasterBoundTokens).not.toBeNull();
            var unboundAndMasterBoundTokensMap = {};
            unboundTokens.forEach(function(unboundToken) {
                unboundAndMasterBoundTokensMap[unboundToken.uniqueKey()] = unboundToken;
            }, this);
            masterBoundTokens.forEach(function(masterBoundToken) {
                unboundAndMasterBoundTokensMap[masterBoundToken.uniqueKey()] = masterBoundToken;
            }, this);
            var unboundAndMasterBoundTokens = [];
            for (var key in unboundAndMasterBoundTokensMap)
                unboundAndMasterBoundTokens.push(unboundAndMasterBoundTokensMap[key]);
            expect(storedMasterBoundTokens).toEqual(unboundAndMasterBoundTokens);

            // This should only return the unbound and master bound-only tokens.
            var storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(storedUserBoundTokens).not.toBeNull();
            expect(storedUserBoundTokens).toEqual(unboundAndMasterBoundTokens);

            // This should only return the unbound tokens.
            var storedUnboundTokens = store.getServiceTokens(null, null);
            expect(storedUnboundTokens).not.toBeNull();
            expect(storedUnboundTokens).toEqual(unboundTokens);
        });
    });

    it("remove no service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var masterBoundTokens, userBoundTokens, unboundTokens;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { userBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundTokens && userBoundTokens && unboundTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);
            store.addServiceTokens(masterBoundTokens);
            store.addServiceTokens(userBoundTokens);
            store.addServiceTokens(unboundTokens);

            store.removeServiceTokens(null, null, null);

            // This should only return the unbound and master bound tokens.
            var storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
            expect(storedMasterBoundTokens).not.toBeNull();
            var unboundAndMasterBoundTokensMap = {};
            unboundTokens.forEach(function(unboundToken) {
                unboundAndMasterBoundTokensMap[unboundToken.uniqueKey()] = unboundToken;
            }, this);
            masterBoundTokens.forEach(function(masterBoundToken) {
                unboundAndMasterBoundTokensMap[masterBoundToken.uniqueKey()] = masterBoundToken;
            }, this);
            var unboundAndMasterBoundTokens = [];
            for (var umtKey in unboundAndMasterBoundTokensMap)
                unboundAndMasterBoundTokens.push(unboundAndMasterBoundTokensMap[umtKey]);
            expect(serviceTokensEqual(unboundAndMasterBoundTokens, storedMasterBoundTokens)).toBeTruthy();

            // This should return all of the tokens.
            var storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(storedUserBoundTokens).not.toBeNull();
            var allTokensMap = {};
            unboundTokens.forEach(function(unboundToken) {
                allTokensMap[unboundToken.uniqueKey()] = unboundToken;
            }, this);
            userBoundTokens.forEach(function(userBoundToken) {
                allTokensMap[userBoundToken.uniqueKey()] = userBoundToken;
            }, this);
            masterBoundTokens.forEach(function(masterBoundToken) {
                allTokensMap[masterBoundToken.uniqueKey()] = masterBoundToken;
            }, this);
            var allTokens = [];
            for (var key in allTokensMap)
                allTokens.push(allTokensMap[key]);
            expect(serviceTokensEqual(allTokens, storedUserBoundTokens)).toBeTruthy();

            // This should only return the unbound tokens.
            var storedUnboundTokens = store.getServiceTokens(null, null);
            expect(storedUnboundTokens).not.toBeNull();
            expect(serviceTokensEqual(unboundTokens, storedUnboundTokens)).toBeTruthy();
        });
    });

    it("remove service tokens by name", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var masterBoundTokens, userBoundTokens, unboundTokens;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { userBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundTokens && userBoundTokens && unboundTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);
            store.addServiceTokens(masterBoundTokens);
            store.addServiceTokens(userBoundTokens);
            store.addServiceTokens(unboundTokens);

            var allTokensMap = {};
            unboundTokens.forEach(function(unboundToken) {
                allTokensMap[unboundToken.uniqueKey()] = unboundToken;
            }, this);
            userBoundTokens.forEach(function(userBoundToken) {
                allTokensMap[userBoundToken.uniqueKey()] = userBoundToken;
            }, this);
            masterBoundTokens.forEach(function(masterBoundToken) {
                allTokensMap[masterBoundToken.uniqueKey()] = masterBoundToken;
            }, this);
            var allTokens = [];
            for (var key in allTokensMap)
                allTokens.push(allTokensMap[key]);

            var random = new Random();
            var removedTokens = [];
            allTokens.forEach(function(token) {
                if (random.nextBoolean()) return;
                store.removeServiceTokens(token.name, token.isMasterTokenBound() ? masterToken : null, token.isUserIdTokenBound() ? userIdToken : null);
                removedTokens.push(token);
            }, this);

            // This should only return tokens that haven't been removed.
            var storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
            expect(storedMasterBoundTokens).not.toBeNull();
            expect(serviceTokensContainsAny(storedMasterBoundTokens, removedTokens)).toBeFalsy();

            // This should only return tokens that haven't been removed.
            var storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(storedUserBoundTokens).not.toBeNull();
            expect(serviceTokensContainsAny(storedUserBoundTokens, removedTokens)).toBeFalsy();

            // This should only return tokens that haven't been removed.
            var storedUnboundTokens = store.getServiceTokens(null, null);
            expect(storedUnboundTokens).not.toBeNull();
            expect(serviceTokensContainsAny(storedUnboundTokens, removedTokens)).toBeFalsy();
        });
    });

    it("clear service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        var masterBoundTokens, userBoundTokens, unboundTokens;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken, {
                result: function(tks) { userBoundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundTokens && userBoundTokens && unboundTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(USER_ID, userIdToken);
            store.addServiceTokens(masterBoundTokens);
            store.addServiceTokens(userBoundTokens);
            store.addServiceTokens(unboundTokens);

            store.clearServiceTokens();

            var storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
            expect(storedMasterBoundTokens).not.toBeNull();
            expect(storedMasterBoundTokens.length).toEqual(0);
            var storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
            expect(storedUserBoundTokens).not.toBeNull();
            expect(storedUserBoundTokens.length).toEqual(0);
            var storedUnboundTokens = store.getServiceTokens(null, null);
            expect(storedUnboundTokens).not.toBeNull();
            expect(storedUserBoundTokens.length).toEqual(0);
        });
    });

    it("get service tokens with mismatched tokens", function() {
        var masterToken, mismatchedMasterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 2, {
                result: function(token) { mismatchedMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken && mismatchedMasterToken; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() {
                store.getServiceTokens(mismatchedMasterToken, userIdToken);
            };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });
    });

    it("get service tokens with missing master token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() {
                store.getServiceTokens(null, userIdToken);
            };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL));
        });
    });

    it("remove service tokens with mismatched tokens", function() {
        var masterToken, mismatchedMasterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 2, {
                result: function(token) { mismatchedMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() {
                store.removeServiceTokens(null, mismatchedMasterToken, userIdToken);
            };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });
    });

    it("removing old master token does not remove service tokens", function() {
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 2, 1, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        var masterBoundServiceTokens, serviceTokensA, serviceTokensB;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterTokenA, {
                result: function(tks) { masterBoundServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA, {
                result: function(tks) { serviceTokensA = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB, {
                result: function(tks) { serviceTokensB = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokens && serviceTokensA && serviceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addServiceTokens(masterBoundServiceTokens);
            store.addServiceTokens(serviceTokensA);
            store.addServiceTokens(serviceTokensB);

            // We still have a master token with serial number 1 so no service
            // tokens should have been deleted.
            store.removeCryptoContext(masterTokenA);
            var storedServiceTokensA = store.getServiceTokens(masterTokenB, userIdTokenA);
            var storedServiceTokensB = store.getServiceTokens(masterTokenB, userIdTokenB);
            var expectedServiceTokensAMap = {};
            masterBoundServiceTokens.forEach(function(masterBoundServiceToken) {
                expectedServiceTokensAMap[masterBoundServiceToken.uniqueKey()] = masterBoundServiceToken;
            }, this);
            serviceTokensA.forEach(function(serviceTokenA) {
                expectedServiceTokensAMap[serviceTokenA.uniqueKey()] = serviceTokenA;
            }, this);
            var expectedServiceTokensA = [];
            for (var aKey in expectedServiceTokensAMap)
                expectedServiceTokensA.push(expectedServiceTokensAMap[aKey]);
            expect(storedServiceTokensA).toEqual(expectedServiceTokensA);
            var expectedServiceTokensBMap = {};
            masterBoundServiceTokens.forEach(function(masterBoundServiceToken) {
                expectedServiceTokensBMap[masterBoundServiceToken.uniqueKey()] = masterBoundServiceToken;
            }, this);
            serviceTokensB.forEach(function(serviceTokenB) {
                expectedServiceTokensBMap[serviceTokenB.uniqueKey()] = serviceTokenB;
            }, this);
            var expectedServiceTokensB = [];
            for (var bKey in expectedServiceTokensBMap)
                expectedServiceTokensB.push(expectedServiceTokensBMap[bKey]);
            expect(storedServiceTokensB).toEqual(expectedServiceTokensB);
        });
    });

    it("removing final master token removes service tokens", function() {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        var masterBoundServiceTokens, serviceTokensA, serviceTokensB;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterTokenA, {
                result: function(tks) { masterBoundServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA, {
                result: function(tks) { serviceTokensA = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB, {
                result: function(tks) { serviceTokensB = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokens && serviceTokensA && serviceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addServiceTokens(masterBoundServiceTokens);
            store.addServiceTokens(serviceTokensA);
            store.addServiceTokens(serviceTokensB);

            // All of master token A's user ID tokens should be deleted.
            store.removeCryptoContext(masterTokenA);
            var storedServiceTokensA = store.getServiceTokens(masterTokenA, userIdTokenA);
            expect(storedServiceTokensA.length).toEqual(0);
            var storedServiceTokensB = store.getServiceTokens(masterTokenB, userIdTokenB);
            expect(serviceTokensEqual(serviceTokensB, storedServiceTokensB)).toBeTruthy();
        });
    });

    it("clear crypto contexts leaves unbound service tokens", function() {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        var unboundServiceTokens, serviceTokensA, serviceTokensB;
        runs(function() {
            MslTestUtils.getServiceTokens(ctx, null, null, {
                result: function(tks) { unboundServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA, {
                result: function(tks) { serviceTokensA = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB, {
                result: function(tks) { serviceTokensB = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return unboundServiceTokens && serviceTokensA && serviceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterTokenA, cryptoContext);
            store.setCryptoContext(masterTokenB, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addServiceTokens(unboundServiceTokens);
            store.addServiceTokens(serviceTokensA);
            store.addServiceTokens(serviceTokensB);

            // All bound service tokens should be deleted.
            store.clearCryptoContexts();
            expect(store.getServiceTokens(masterTokenA, userIdTokenA)).toEqual(unboundServiceTokens);
            expect(store.getServiceTokens(masterTokenB, userIdTokenB)).toEqual(unboundServiceTokens);
            var storedServiceTokens = store.getServiceTokens(null, null);
            expect(serviceTokensEqual(unboundServiceTokens, storedServiceTokens)).toBeTruthy();
        });
    });

    it("remove user ID token removes correct service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        var masterBoundServiceTokens, serviceTokensA, serviceTokensB;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenA, {
                result: function(tks) { serviceTokensA = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenB, {
                result: function(tks) { serviceTokensB = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokens && serviceTokensA && serviceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addServiceTokens(masterBoundServiceTokens);
            store.addServiceTokens(serviceTokensA);
            store.addServiceTokens(serviceTokensB);

            // We should still have all the master token bound and user ID token B
            // bound service tokens.
            store.removeUserIdToken(userIdTokenA);
            var storedServiceTokens = store.getServiceTokens(masterToken, userIdTokenB);
            var expectedServiceTokensMap = {};
            masterBoundServiceTokens.forEach(function(token) {
                expectedServiceTokensMap[token.uniqueKey()] = token;
            }, this);
            serviceTokensB.forEach(function(token) {
                expectedServiceTokensMap[token.uniqueKey()] = token;
            }, this);
            var expectedServiceTokens = [];
            for (var key in expectedServiceTokensMap)
                expectedServiceTokens.push(expectedServiceTokensMap[key]);
            expect(serviceTokensEqual(expectedServiceTokens, storedServiceTokens)).toBeTruthy();
        });
    });

    it("clearing user ID tokens removes correct service tokens", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);

        var masterBoundServiceTokens, serviceTokensA, serviceTokensB;
        runs(function() {
            MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken, {
                result: function(tks) { masterBoundServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenA, {
                result: function(tks) { serviceTokensA = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenB, {
                result: function(tks) { serviceTokensB = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokens && serviceTokensA && serviceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        runs(function() {
            var cryptoContext = new NullCryptoContext();
            var userIdA = USER_ID + "A";
            var userIdB = USER_ID + "B";

            store.setCryptoContext(masterToken, cryptoContext);
            store.addUserIdToken(userIdA, userIdTokenA);
            store.addUserIdToken(userIdB, userIdTokenB);
            store.addServiceTokens(masterBoundServiceTokens);
            store.addServiceTokens(serviceTokensA);
            store.addServiceTokens(serviceTokensB);

            // Only the master token bound service tokens should be left.
            store.clearUserIdTokens();
            var storedServiceTokens = store.getServiceTokens(masterToken, userIdTokenB);
            expect(serviceTokensEqual(masterBoundServiceTokens, storedServiceTokens)).toBeTruthy();
        });
    });

    /**
     * Service token add/remove stress test runner.
     * 
     * Randomly adds or removes service tokens in combinations of unbound,
     * master token bound, and user ID token bound Also iterates through the
     * service tokens.
     * 
     * @param ctx MSL context.
     * @param store MSL store.
     * @param count the number of master token and user ID tokens to create
     *        combinations of.
     * @param callback
     */
    function serviceTokenStressor(ctx, store, count, callback) {
        var r = new Random();
        for (var i = 0; i < count; ++i) {
            var tokenIndex = r.nextInt(count);
            MslTestUtils.getMasterToken(ctx, tokenIndex, 1, {
                result: function(masterToken) {
                    var userId = r.nextInt(count);
                    MslTestUtils.getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory.USER, {
                        result: function(userIdToken) {
                            var option = r.nextInt(6);
                            switch (option) {
                                case 0:
                                {
                                    MslTestUtils.getServiceTokens(ctx, null, null, {
                                        result: function(tks) {
                                            store.addServiceTokens(tks);
                                            callback.add(1);
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                    break;
                                }
                                case 1:
                                {
                                    store.setCryptoContext(masterToken, new NullCryptoContext());
                                    MslTestUtils.getServiceTokens(ctx, masterToken, null, {
                                        result: function(tks) {
                                            store.addServiceTokens(tks);
                                            callback.add(1);
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                    break;
                                }
                                case 2:
                                {
                                    store.setCryptoContext(masterToken, new NullCryptoContext());
                                    store.addUserIdToken(USER_ID + userId, userIdToken);
                                    MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken, {
                                        result: function(tks) {
                                            store.addServiceTokens(tks);
                                            callback.add(1);
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                    break;
                                }
                                case 3:
                                {
                                    store.getServiceTokens(null, null);
                                    callback.add(1);
                                    break;
                                }
                                case 4:
                                {
                                    store.getServiceTokens(masterToken, null);
                                    callback.add(1);
                                    break;
                                }
                                case 5:
                                {
                                    store.getServiceTokens(masterToken, userIdToken);
                                    callback.add(1);
                                    break;
                                }
                            }
                        },
                        error: function(err) { callback.error(new MslInternalException("Unexpected service token stressor exception.", err)); }
                    });
                },
                error: function(err) { callback.error(new MslInternalException("Unexpected service token stressor exception.", err)); }
            });
        }
    }

    it("service token stress test", function() {
        var ops = 0;
        runs(function() {
            for (var i = 0; i < 5 * MAX_TOKENS; ++i) {
                serviceTokenStressor(ctx, store, MAX_TOKENS, {
                    add: function(r) { ops += r; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
        });
        waitsFor(function() { return ops == 5 * MAX_TOKENS * MAX_TOKENS; }, "service token stress test to complete", 50 * MslTestConstants.TIMEOUT);
    });
});