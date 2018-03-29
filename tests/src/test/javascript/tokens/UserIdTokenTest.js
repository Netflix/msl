/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * User ID token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UserIdToken", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UserIdToken = require('msl-core/tokens/UserIdToken.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;

    /** Key token data. */
    var KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /** Key renewal window timestamp. */
    var KEY_RENEWAL_WINDOW = "renewalwindow";
    /** Key expiration timestamp. */
    var KEY_EXPIRATION = "expiration";
    /** Key master token serial number. */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** Key user ID token serial number. */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /** Key token user identification data. */
    var KEY_USERDATA = "userdata";

    // userdata
    /** Key issuer data. */
    var KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    var KEY_IDENTITY = "identity";

    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;

    var RENEWAL_WINDOW = new Date(Date.now() + 120000);
    var EXPIRATION = new Date(Date.now() + 180000);
    var MASTER_TOKEN;
    var SERIAL_NUMBER = 42;
    var ISSUER_DATA;
    var USER = MockEmailPasswordAuthenticationFactory.USER;

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
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(token) { MASTER_TOKEN = token; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                ISSUER_DATA = encoder.parseObject(TextEncoding.getBytes("{ \"issuerid\" : 17 }"));
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", MslTestConstants.TIMEOUT);
            runs(function() { initialized = true; });
        }
    });

    it("ctors", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            expect(userIdToken.isDecrypted()).toBeTruthy();
            expect(userIdToken.isVerified()).toBeTruthy();
            expect(userIdToken.isRenewable(null)).toBeFalsy();
            expect(userIdToken.isExpired(null)).toBeFalsy();
            expect(userIdToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(userIdToken.issuerData).toEqual(ISSUER_DATA);
            expect(userIdToken.user).toEqual(USER);
            expect(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND));
            expect(userIdToken.mtSerialNumber).toEqual(MASTER_TOKEN.serialNumber);
            expect(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND));
            expect(userIdToken.serialNumber).toEqual(SERIAL_NUMBER);
            userIdToken.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "enocde", MslTestConstants.TIMEOUT);

        var moUserIdToken;
        runs(function() {
            var mo = encoder.parseObject(encode);
            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function(token) { moUserIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moUserIdToken; }, "moUserIdToken", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moUserIdToken.isDecrypted()).toEqual(userIdToken.isDecrypted());
            expect(moUserIdToken.isVerified()).toEqual(userIdToken.isVerified());
            expect(moUserIdToken.isRenewable(null)).toEqual(userIdToken.isRenewable(null));
            expect(moUserIdToken.isExpired(null)).toEqual(userIdToken.isExpired(null));
            expect(moUserIdToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(moUserIdToken.issuerData).toEqual(userIdToken.issuerData);
            expect(moUserIdToken.user).toEqual(userIdToken.user);
            expect(moUserIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
            expect(moUserIdToken.mtSerialNumber).toEqual(userIdToken.mtSerialNumber);
            expect(moUserIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            expect(moUserIdToken.serialNumber).toEqual(userIdToken.serialNumber);
            moUserIdToken.toMslEncoding(encoder, ENCODER_FORMAT, {
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

    it("negative serial number ctor", function() {
        var serialNumber = -1;

        var exception;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("too large serial number ctor", function() {
        var serialNumber = MslConstants.MAX_LONG_VALUE + 2;

        var exception;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("null master token", function() {
        var exception;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, null, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("master token mismtached", function() {
        var masterToken, joMasterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { joMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken && joMasterToken; }, "master token", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(mo) {
                    UserIdToken.parse(ctx, mo, joMasterToken, {
                        result: function() {},
                        error: function(e) { exception = e; },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });	
    });

    it("master token null", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(mo) {
                    UserIdToken.parse(ctx, mo, null, {
                        result: function() {},
                        error: function(e) { exception = e; },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });
    });

    it("inconsistent expiration", function() {
        var expiration = new Date(Date.now() - 1);
        var renewalWindow = new Date();
        expect(expiration.getTime()).toBeLessThan(renewalWindow.getTime());

        var exception;
        runs(function() {
            UserIdToken.create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("inconsistent expiration json", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_EXPIRATION, (Date.now() / MILLISECONDS_PER_SECOND) - 1);
            tokendataMo.put(KEY_RENEWAL_WINDOW, Date.now() / MILLISECONDS_PER_SECOND);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL));
        });
    });

    it("missing tokendata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.remove(KEY_TOKENDATA);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
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

    it("invalid tokendata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            ++tokendata[0];
            mo.put(KEY_TOKENDATA, tokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.NONE));
        });
    });

    it("missing signature", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.remove(KEY_SIGNATURE);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
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

    it("missing renewal window", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_RENEWAL_WINDOW);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid renewal window", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_RENEWAL_WINDOW, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("missing expiration", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_EXPIRATION);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid expiration", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_EXPIRATION, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("missing serial number", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_SERIAL_NUMBER);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid serial number", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("negative serial number ctor", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, -1);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("too large serial number ctor", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("missing master token serial number", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_MASTER_TOKEN_SERIAL_NUMBER);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid master token serial number", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("negative master token serial number ctor", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("too large master token serial number ctor", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("missing userdata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_USERDATA);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, modifiedTokendata);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid userdata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_USERDATA, "x");

            cryptoContext = ctx.getMslCryptoContext();
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                        result: function() {},
                        error: function(e) { exception = e; },
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("empty userdata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);

            cryptoContext = ctx.getMslCryptoContext();
            var ciphertext = new Uint8Array(0);
            tokendataMo.put(KEY_USERDATA, ciphertext);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                        result: function() {},
                        error: function(e) { exception = e; },
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_USERDATA_MISSING));
        });
    });

    it("corrupt userdata", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, modifiedTokendata;
        runs(function() {
            // This is testing user data that is verified but corrupt.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var userdata = tokendataMo.getBytes(KEY_USERDATA);
            ++userdata[userdata.length-1];
            tokendataMo.put(KEY_USERDATA, userdata);

            cryptoContext = ctx.getMslCryptoContext();
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                        result: function() {},
                        error: function(e) { exception = e; },
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });

    it("invalid user", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the user data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_USERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var userdataMo = encoder.parseObject(plaintext);

                    // After modifying the user data we need to encrypt it.
                    userdataMo.put(KEY_IDENTITY, encoder.createObject());
                    encoder.encodeObject(userdataMo, ENCODER_FORMAT, {
                        result: function(modifiedUserdata) {
                            cryptoContext.encrypt(modifiedUserdata, encoder, ENCODER_FORMAT, {
                                result: function(userdata) {
                                    tokendataMo.put(KEY_USERDATA, userdata);

                                    // The tokendata must be signed otherwise the user data will not be
                                    // processed.
                                    encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                                        result: function(modifiedTokendata) {
                                            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                                                result: function(signature) {
                                                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                                                    mo.put(KEY_SIGNATURE, signature);

                                                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                                                        result: function() {},
                                                        error: function(e) { exception = e; },
                                                    });	
                                                },
                                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                            });
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
        });
    });

    it("empty user", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the user data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_USERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var userdataMo = encoder.parseObject(plaintext);

                    // After modifying the user data we need to encrypt it.
                    userdataMo.put(KEY_IDENTITY, "");
                    encoder.encodeObject(userdataMo, ENCODER_FORMAT, {
                        result: function(modifiedUserdata) {
                            cryptoContext.encrypt(modifiedUserdata, encoder, ENCODER_FORMAT, {
                                result: function(userdata) {
                                    tokendataMo.put(KEY_USERDATA, userdata);

                                    // The tokendata must be signed otherwise the user data will not be
                                    // processed.
                                    encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                                        result: function(modifiedTokendata) {
                                            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                                                result: function(signature) {
                                                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                                                    mo.put(KEY_SIGNATURE, signature);

                                                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                                                        result: function() {},
                                                        error: function(e) { exception = e; },
                                                    });	
                                                },
                                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                            });
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID));
        });
    });

    it("missing user", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the user data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_USERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var userdataMo = encoder.parseObject(plaintext);

                    // After modifying the user data we need to encrypt it.
                    userdataMo.remove(KEY_IDENTITY);
                    encoder.encodeObject(userdataMo, ENCODER_FORMAT, {
                        result: function(modifiedUserdata) {
                            cryptoContext.encrypt(modifiedUserdata, encoder, ENCODER_FORMAT, {
                                result: function(userdata) {
                                    tokendataMo.put(KEY_USERDATA, userdata);

                                    // The tokendata must be signed otherwise the user data will not be
                                    // processed.
                                    encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                                        result: function(modifiedTokendata) {
                                            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                                                result: function(signature) {
                                                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                                                    mo.put(KEY_SIGNATURE, signature);

                                                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                                                        result: function() {},
                                                        error: function(e) { exception = e; },
                                                    });
                                                },
                                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                            });
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
        });
    });

    it("invalid issuer data", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the user data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_USERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var userdataMo = encoder.parseObject(plaintext);

                    // After modifying the user data we need to encrypt it.
                    userdataMo.put(KEY_ISSUER_DATA, "x");
                    encoder.encodeObject(userdataMo, ENCODER_FORMAT, {
                        result: function(modifiedUserdata) {
                            cryptoContext.encrypt(modifiedUserdata, encoder, ENCODER_FORMAT, {
                                result: function(userdata) {
                                    tokendataMo.put(KEY_USERDATA, userdata);

                                    // The tokendata must be signed otherwise the user data will not be
                                    // processed.
                                    encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                                        result: function(modifiedTokendata) {
                                            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                                                result: function(signature) {
                                                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                                                    mo.put(KEY_SIGNATURE, signature);

                                                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                                                        result: function() {},
                                                        error: function(e) { exception = e; },
                                                    });	
                                                },
                                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                            });
                                        },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                                    });
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
        });
    });

    it("not verified", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var encode;
        runs(function() {
            userIdToken.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "enocde", MslTestConstants.TIMEOUT);

        var moUserIdToken;
        runs(function() {
            var mo = encoder.parseObject(encode);

            var signature = mo.getBytes(KEY_SIGNATURE);
            ++signature[0];
            mo.put(KEY_SIGNATURE, signature);

            UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                result: function(token) { moUserIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moUserIdToken; }, "moUserIdToken", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moUserIdToken.isDecrypted()).toBeFalsy();
            expect(moUserIdToken.isVerified()).toBeFalsy();
            expect(moUserIdToken.isRenewable(null)).not.toEqual(userIdToken.isRenewable(null));
            expect(moUserIdToken.isExpired(null)).toEqual(userIdToken.isExpired(null));
            expect(moUserIdToken.isBoundTo(MASTER_TOKEN)).toEqual(userIdToken.isBoundTo(MASTER_TOKEN));
            expect(moUserIdToken.user).toBeNull();
            expect(moUserIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
            expect(moUserIdToken.mtSerialNumber).toEqual(userIdToken.mtSerialNumber);
            expect(moUserIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            expect(moUserIdToken.serialNumber).toEqual(userIdToken.serialNumber);moUserIdToken.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).not.toEqual(encode);
        });
    });

    it("is renewable", function() {
        var renewalWindow = new Date();
        var expiration = new Date(Date.now() + 10000);
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);
        runs(function() {
            var now = new Date();
            expect(userIdToken.isRenewable(null)).toBeTruthy();
            expect(userIdToken.isRenewable(now)).toBeTruthy();
            expect(userIdToken.isExpired(null)).toBeFalsy();
            expect(userIdToken.isExpired(now)).toBeFalsy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(userIdToken.isRenewable(before)).toBeFalsy();
            expect(userIdToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(userIdToken.isRenewable(after)).toBeTruthy();
            expect(userIdToken.isExpired(after)).toBeTruthy();
        });
    });

    it("is expired", function() {
        var renewalWindow = new Date(Date.now() - 10000);
        var expiration = new Date();
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);
        runs(function() {
            var now = new Date();
            expect(userIdToken.isRenewable(null)).toBeTruthy();
            expect(userIdToken.isRenewable(now)).toBeTruthy();
            expect(userIdToken.isExpired(null)).toBeTruthy();
            expect(userIdToken.isExpired(now)).toBeTruthy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(userIdToken.isRenewable(before)).toBeFalsy();
            expect(userIdToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(userIdToken.isRenewable(after)).toBeTruthy();
            expect(userIdToken.isExpired(after)).toBeTruthy();
        });
    });

    it("not renewable or expired", function() {
        var renewalWindow = new Date(Date.now() + 10000);
        var expiration = new Date(Date.now() + 20000);
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);
        runs(function() {
            var now = new Date();
            expect(userIdToken.isRenewable(null)).toBeFalsy();
            expect(userIdToken.isRenewable(now)).toBeFalsy();
            expect(userIdToken.isExpired(null)).toBeFalsy();
            expect(userIdToken.isExpired(now)).toBeFalsy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(userIdToken.isRenewable(before)).toBeFalsy();
            expect(userIdToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(userIdToken.isRenewable(after)).toBeTruthy();
            expect(userIdToken.isExpired(after)).toBeTruthy();
        });
    });

    it("is bound to master token", function() {
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(userIdTokenA.isBoundTo(masterTokenA)).toBeTruthy();
            expect(userIdTokenA.isBoundTo(masterTokenB)).toBeFalsy();
            expect(userIdTokenA.isBoundTo(null)).toBeFalsy();
            expect(userIdTokenB.isBoundTo(masterTokenB)).toBeTruthy();
            expect(userIdTokenB.isBoundTo(masterTokenA)).toBeFalsy();
            expect(userIdTokenB.isBoundTo(null)).toBeFalsy();
        });
    });

    it("equals serial number", function() {
        var serialNumberA = 1;
        var serialNumberB = 2;
        var userIdTokenA, userIdTokenB;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberA, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberB, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens", MslTestConstants.TIMEOUT);
        var userIdTokenA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdTokenA, {
                result: function(mo) {
                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                        result: function(token) { userIdTokenA2 = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA2; }, "user ID token parsed", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(userIdTokenA.equals(userIdTokenA)).toBeTruthy();
            expect(userIdTokenA.uniqueKey()).toEqual(userIdTokenA.uniqueKey());

            expect(userIdTokenA.equals(userIdTokenB)).toBeFalsy();
            expect(userIdTokenB.equals(userIdTokenA)).toBeFalsy();
            expect(userIdTokenB.uniqueKey()).not.toEqual(userIdTokenA.uniqueKey());

            expect(userIdTokenA.equals(userIdTokenA2)).toBeTruthy();
            expect(userIdTokenA2.equals(userIdTokenA)).toBeTruthy();
            expect(userIdTokenA2.uniqueKey()).toEqual(userIdTokenA.uniqueKey());
        });
    });

    it("equals master token serial number", function() {
        var masterTokenA, masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
            MslTestUtils.getMasterToken(ctx, 1, 2, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT);

        var userIdTokenA, userIdTokenB;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens", MslTestConstants.TIMEOUT);

        var userIdTokenA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, userIdTokenA, {
                result: function(mo) {
                    UserIdToken.parse(ctx, mo, MASTER_TOKEN, {
                        result: function(token) { userIdTokenA2 = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA2; }, "user ID token parsed", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(userIdTokenA.equals(userIdTokenA)).toBeTruthy();
            expect(userIdTokenA.uniqueKey()).toEqual(userIdTokenA.uniqueKey());

            expect(userIdTokenA.equals(userIdTokenB)).toBeFalsy();
            expect(userIdTokenB.equals(userIdTokenA)).toBeFalsy();
            expect(userIdTokenB.uniqueKey()).not.toEqual(userIdTokenA.uniqueKey());

            expect(userIdTokenA.equals(userIdTokenA2)).toBeTruthy();
            expect(userIdTokenA2.equals(userIdTokenA)).toBeTruthy();
            expect(userIdTokenA2.uniqueKey()).toEqual(userIdTokenA.uniqueKey());
        });
    });

    it("equals object", function() {
        var userIdToken;
        runs(function() {
            UserIdToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(userIdToken.equals(null)).toBeFalsy();
            expect(userIdToken.equals(RENEWAL_WINDOW)).toBeFalsy();
        });
    });
});
