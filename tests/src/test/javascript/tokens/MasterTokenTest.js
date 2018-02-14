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
 * Master token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MasterToken", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
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
    /** Key sequence number. */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key serial number. */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /** Key session data. */
    var KEY_SESSIONDATA = "sessiondata";

    // sessiondata
    /** Key issuer data. */
    var KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    var KEY_IDENTITY = "identity";
    /** Key symmetric encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key encryption algorithm. */
    var KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /** Key symmetric HMAC key. */
    var KEY_HMAC_KEY = "hmackey";
    /** Key signature key. */
    var KEY_SIGNATURE_KEY = "signaturekey";
    /** Key signature algorithm. */
    var KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";

    var RENEWAL_WINDOW = new Date(Date.now() + 120000);
    var EXPIRATION = new Date(Date.now() + 180000);
    var SEQUENCE_NUMBER = 1;
    var SERIAL_NUMBER = 42;
    var ISSUER_DATA;
    var IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    var ENCRYPTION_KEY;
    var SIGNATURE_KEY;

    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;

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
                ISSUER_DATA = encoder.parseObject(TextEncoding.getBytes("{ \"issuerid\" : 17 }"));

                // These keys won't exist until after the factory is instantiated.
                ENCRYPTION_KEY = MockPresharedAuthenticationFactory.KPE;
                SIGNATURE_KEY = MockPresharedAuthenticationFactory.KPH;

                initialized = true;
            });
        }
    });

    function incrementSequenceNumber(seqNo, amount) {
        if (seqNo - MslConstants.MAX_LONG_VALUE + amount <= 0)
            return seqNo + amount;
        return seqNo - MslConstants.MAX_LONG_VALUE - 1 + amount;
    }

    function decrementSequenceNumber(seqNo, amount) {
        if (seqNo - amount >= 0)
            return seqNo - amount;
        return MslConstants.MAX_LONG_VALUE - amount - 1 + seqNo;
    }

    it("ctors", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var encode;
        runs(function() {
            expect(masterToken.isDecrypted()).toBeTruthy();
            expect(masterToken.isVerified()).toBeTruthy();
            expect(masterToken.isRenewable(null)).toBeFalsy();
            expect(masterToken.isExpired(null)).toBeFalsy();
            expect(masterToken.isNewerThan(masterToken)).toBeFalsy();
            expect(masterToken.encryptionKey.toByteArray()).toEqual(ENCRYPTION_KEY.toByteArray());
            expect(masterToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND));
            expect(masterToken.signatureKey.toByteArray()).toEqual(SIGNATURE_KEY.toByteArray());
            expect(masterToken.identity).toEqual(IDENTITY);
            expect(masterToken.issuerData).toEqual(ISSUER_DATA);
            expect(masterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND));
            expect(masterToken.sequenceNumber).toEqual(SEQUENCE_NUMBER);
            expect(masterToken.serialNumber).toEqual(SERIAL_NUMBER);
            masterToken.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            expect(encode).not.toBeNull();

            var mo = encoder.parseObject(encode);
            MasterToken.parse(ctx, mo, {
                result: function(token) { moMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var moEncode;
        runs(function() {
            expect(moMasterToken.isDecrypted()).toEqual(masterToken.isDecrypted());
            expect(moMasterToken.isVerified()).toEqual(masterToken.isVerified());
            expect(moMasterToken.isRenewable(null)).toEqual(masterToken.isRenewable(null));
            expect(moMasterToken.isExpired(null)).toEqual(masterToken.isExpired(null));
            expect(moMasterToken.isNewerThan(masterToken)).toBeFalsy();
            expect(masterToken.isNewerThan(moMasterToken)).toBeFalsy();
            expect(moMasterToken.encryptionKey.toByteArray()).toEqual(masterToken.encryptionKey.toByteArray());
            expect(moMasterToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
            expect(moMasterToken.signatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
            expect(moMasterToken.identity).toEqual(masterToken.identity);
            expect(moMasterToken.issuerData).toEqual(masterToken.issuerData);
            expect(moMasterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            expect(moMasterToken.sequenceNumber).toEqual(masterToken.sequenceNumber);
            expect(moMasterToken.serialNumber).toEqual(masterToken.serialNumber);

            moMasterToken.toMslEncoding(encoder, ENCODER_FORMAT, {
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

    it("negative sequence number ctor", function() {
        var exception;
        runs(function() {
            var sequenceNumber = -1;
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("too large sequence number ctor", function() {
        var exception;
        runs(function() {
            var sequenceNumber = MslConstants.MAX_LONG_VALUE + 2;
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("negative serial number ctor", function() {
        var exception;
        runs(function() {
            var serialNumber = -1;
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("too large serial number ctor", function() {
        var exception;
        runs(function() {
            var serialNumber = MslConstants.MAX_LONG_VALUE + 2;
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("inconsistent expiration", function() {
        var exception;
        runs(function() {
            var expiration = new Date(Date.now() - 1000);
            var renewalWindow = new Date();
            expect(expiration.getTime()).toBeLessThan(renewalWindow.getTime());
            MasterToken.create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException());
        });
    });

    it("inconsistent expiration parse", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_EXPIRATION, (Date.now() / MILLISECONDS_PER_SECOND) - 1);
            tokendataMo.put(KEY_RENEWAL_WINDOW, Date.now() / MILLISECONDS_PER_SECOND);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL));
        });
    });

    it("null issuer data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, null, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            expect(masterToken.issuerData).toBeNull();

            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            MasterToken.parse(ctx, mo, {
                result: function(token) { moMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            expect(moMasterToken.issuerData).toBeNull();
        });
    });

    it("missing tokendata", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.remove(KEY_TOKENDATA);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("invalid tokendata", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
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

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.NONE));
        });
    });

    it("missing signature", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.remove(KEY_SIGNATURE);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

    it("missing renewal window", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_RENEWAL_WINDOW);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid renewal window", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_RENEWAL_WINDOW, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("missing expiration", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_EXPIRATION);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid expiration", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_EXPIRATION, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("missing sequence number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_SEQUENCE_NUMBER);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid sequence number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SEQUENCE_NUMBER, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("negative sequence number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SEQUENCE_NUMBER, -1);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });

    it("too large sequence number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE));
        });
    });

    it("missing serial number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_SERIAL_NUMBER);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });


    it("invalid serial number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("negative serial number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, -1);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("too large serial number", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });

    it("missing session data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var tokendataEncode;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.remove(KEY_SESSIONDATA);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { tokendataEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokendataEncode; }, "tokendataEncode", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mo.put(KEY_TOKENDATA, tokendataEncode);

            MasterToken.parse(ctx, mo, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("invalid session data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            tokendataMo.put(KEY_SESSIONDATA, "x");
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; },
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
        });
    });

    it("empty session data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);

            var ciphertext = new Uint8Array(0);
            tokendataMo.put(KEY_SESSIONDATA, ciphertext);
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SESSIONDATA_MISSING));
        });
    });

    it("corrupt session data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            // This is testing session data that is verified but corrupt.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            var tokendataMo = encoder.parseObject(tokendata);
            var sessiondata = tokendataMo.getBytes(KEY_SESSIONDATA);
            ++sessiondata[sessiondata.length-1];
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var cryptoContext = ctx.getMslCryptoContext();
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; },
                    });	        		
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });

    it("not verified", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var encode;
        runs(function() {
            masterToken.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

        var mo, moMasterToken;
        runs(function() {
            mo = encoder.parseObject(encode);

            var signature = mo.getBytes(KEY_SIGNATURE);
            ++signature[0];
            mo.put(KEY_SIGNATURE, signature);

            MasterToken.parse(ctx, mo, {
                result: function(token) { moMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var moEncode;
        runs(function() {
            expect(moMasterToken.isDecrypted()).toBeFalsy();
            expect(moMasterToken.isVerified()).toBeFalsy();
            expect(moMasterToken.isRenewable(null)).not.toEqual(masterToken.isRenewable(null));
            expect(moMasterToken.isExpired(null)).toEqual(masterToken.isExpired(null));
            expect(moMasterToken.isNewerThan(masterToken)).toBeFalsy();
            expect(masterToken.isNewerThan(moMasterToken)).toBeFalsy();
            expect(moMasterToken.encryptionKey).toBeNull();
            expect(moMasterToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
            expect(moMasterToken.signatureKey).toBeNull();
            expect(moMasterToken.identity).toBeNull();
            expect(moMasterToken.issuerData).toBeNull();
            expect(moMasterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            expect(moMasterToken.sequenceNumber).toEqual(masterToken.sequenceNumber);
            expect(moMasterToken.serialNumber).toEqual(masterToken.serialNumber);
            moMasterToken.toMslEncoding(encoder, ENCODER_FORMAT, {
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

    it("invalid issuer data", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.put(KEY_ISSUER_DATA, "x");
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });	    	    	        		
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
        });
    });

    it("missing identity", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_IDENTITY);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
        });
    });

    it("missing encryption key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_ENCRYPTION_KEY);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
        });
    });

    it("invalid encryption key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.put(KEY_ENCRYPTION_KEY, "");
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR));
        });
    });

    it("missing encryption algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_ENCRYPTION_ALGORITHM);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function(x) { moMasterToken = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            // Confirm default algorithm.
            var moEncryptionKey = moMasterToken.encryptionKey;
            expect(MslTestUtils.Algorithm.equals(WebCryptoAlgorithm.AES_CBC, moEncryptionKey.algorithm)).toBeTruthy();
        });
    });

    it("invalid encryption algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.put(KEY_ENCRYPTION_ALGORITHM, "x");
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM));
        });
    });

    it("missing HMAC key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_HMAC_KEY);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function(x) { moMasterToken = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            // Confirm signature key.
            var moSignatureKey = moMasterToken.signatureKey;
            expect(moSignatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
        });
    });

    it("missing signature key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_SIGNATURE_KEY);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function(x) { moMasterToken = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            // Confirm signature key.
            var moSignatureKey = moMasterToken.signatureKey;
            expect(moSignatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
        });
    });

    it("missing signature algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_SIGNATURE_ALGORITHM);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
            encoder.encodeObject(tokendataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedTokendata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedTokendata; }, "modifiedTokendata", MslTestConstants.TIMEOUT);

        var moMasterToken;
        runs(function() {
            cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT, {
                result: function(signature) {
                    mo.put(KEY_TOKENDATA, modifiedTokendata);
                    mo.put(KEY_SIGNATURE, signature);

                    MasterToken.parse(ctx, mo, {
                        result: function(x) { moMasterToken = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moMasterToken; }, "moMasterToken", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            // Confirm default algorithm.
            var moSignatureKey = moMasterToken.signatureKey;
            expect(MslTestUtils.Algorithm.equals(WebCryptoAlgorithm.HMAC_SHA256, moSignatureKey.algorithm)).toBeTruthy();
        });
    });

    it("invalid signature algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.put(KEY_SIGNATURE_ALGORITHM, "x");
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    }); 
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM));
        });
    });

    it("missing HMAC and signature key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.remove(KEY_HMAC_KEY);
            sessiondataMo.remove(KEY_SIGNATURE_KEY);
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });	
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
        });
    });

    it("invalid HMAC and signature key", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, tokendataMo, plaintext;
        runs(function() {
            cryptoContext = ctx.getMslCryptoContext();

            // Before modifying the session data we need to decrypt it.
            var tokendata = mo.getBytes(KEY_TOKENDATA);
            tokendataMo = encoder.parseObject(tokendata);
            var ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var sessiondataMo = encoder.parseObject(plaintext);

            // After modifying the session data we need to encrypt it.
            sessiondataMo.put(KEY_HMAC_KEY, "");
            sessiondataMo.put(KEY_SIGNATURE_KEY, "");
            encoder.encodeObject(sessiondataMo, ENCODER_FORMAT, {
                result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modifiedPlaintext", MslTestConstants.TIMEOUT);

        var sessiondata;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { sessiondata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sessiondata; }, "sessiondata", MslTestConstants.TIMEOUT);

        var modifiedTokendata;
        runs(function() {
            tokendataMo.put(KEY_SESSIONDATA, sessiondata);

            // The tokendata must be signed otherwise the session data will not be
            // processed.
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

                    MasterToken.parse(ctx, mo, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });	    	        		
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });	
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR));
        });
    });

    it("is renewable", function() {
        var renewalWindow = new Date();
        var expiration = new Date(Date.now() + 10000);
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var now = new Date();
            expect(masterToken.isRenewable(null)).toBeTruthy();
            expect(masterToken.isRenewable(now)).toBeTruthy();
            expect(masterToken.isExpired(null)).toBeFalsy();
            expect(masterToken.isExpired(now)).toBeFalsy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(masterToken.isRenewable(before)).toBeFalsy();
            expect(masterToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(masterToken.isRenewable(after)).toBeTruthy();
            expect(masterToken.isExpired(after)).toBeTruthy();
        });
    });

    it("is expired", function() {
        var renewalWindow = new Date(Date.now() - 1000);
        var expiration = new Date();
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var now = new Date();
            expect(masterToken.isRenewable(null)).toBeTruthy();
            expect(masterToken.isRenewable(now)).toBeTruthy();
            expect(masterToken.isExpired(null)).toBeTruthy();
            expect(masterToken.isExpired(now)).toBeTruthy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(masterToken.isRenewable(before)).toBeFalsy();
            expect(masterToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(masterToken.isRenewable(after)).toBeTruthy();
            expect(masterToken.isExpired(after)).toBeTruthy();
        });
    });

    it("not renewable or expired", function() {
        var renewalWindow = new Date(Date.now() + 1000);
        var expiration = new Date(Date.now() + 2000);
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            var now = new Date();
            expect(masterToken.isRenewable(null)).toBeFalsy();
            expect(masterToken.isRenewable(now)).toBeFalsy();
            expect(masterToken.isExpired(null)).toBeFalsy();
            expect(masterToken.isExpired(now)).toBeFalsy();

            var before = new Date(renewalWindow.getTime() - 1000);
            expect(masterToken.isRenewable(before)).toBeFalsy();
            expect(masterToken.isExpired(before)).toBeFalsy();

            var after = new Date(expiration.getTime() + 1000);
            expect(masterToken.isRenewable(after)).toBeTruthy();
            expect(masterToken.isExpired(after)).toBeTruthy();
        });
    });

    it("is newer than with different sequence numbers", function() {
        var sequenceNumberA = 1;
        var sequenceNumberB = 2;
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterTokenB.isNewerThan(masterTokenA)).toBeTruthy();
            expect(masterTokenA.isNewerThan(masterTokenB)).toBeFalsy();
            expect(masterTokenA.isNewerThan(masterTokenA)).toBeFalsy();
        });
    });

    it("is newer than with different sequence numbers and wraparound", function() {
        // Anything within 128 is newer.
        for (var seqNo = MslConstants.MAX_LONG_VALUE - 127; seqNo <= MslConstants.MAX_LONG_VALUE && seqNo != 0; seqNo = incrementSequenceNumber(seqNo, 1)) {
            // Copy seqNo because we need a local variable for the runs
            // functions.
            var zero = seqNo;
            var minus1 = decrementSequenceNumber(zero, 1);
            var plus1 = incrementSequenceNumber(zero, 1);
            var plus127 = incrementSequenceNumber(zero, 127); 
            var plus128 = incrementSequenceNumber(zero, 128);

            var masterToken;
            var minus1MasterToken, plus1MasterToken;
            var plus127MasterToken, plus128MasterToken;
            runs(function() {
                MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, zero, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                    result: function(x) { masterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, minus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                    result: function(x) { minus1MasterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, plus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                    result: function(x) { plus1MasterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, plus127, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                    result: function(x) { plus127MasterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, plus128, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                    result: function(x) { plus128MasterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken && minus1MasterToken && plus1MasterToken && plus127MasterToken && plus128MasterToken; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                expect(minus1MasterToken.isNewerThan(masterToken)).toBeFalsy();
                expect(masterToken.isNewerThan(minus1MasterToken)).toBeTruthy();
                expect(plus1MasterToken.isNewerThan(masterToken)).toBeTruthy();
                expect(masterToken.isNewerThan(plus1MasterToken)).toBeFalsy();
                expect(plus127MasterToken.isNewerThan(masterToken)).toBeTruthy();
                expect(masterToken.isNewerThan(plus127MasterToken)).toBeFalsy();
                expect(plus128MasterToken.isNewerThan(masterToken)).toBeFalsy();
                expect(masterToken.isNewerThan(plus128MasterToken)).toBeTruthy();
            });
        }
    });

    it("is newer than with different expirations", function() {
        var expirationA = new Date(EXPIRATION.getTime());
        var expirationB = new Date(EXPIRATION.getTime() + 10000);
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", 1000);
        runs(function() {
            expect(masterTokenB.isNewerThan(masterTokenA)).toBeTruthy();
            expect(masterTokenA.isNewerThan(masterTokenB)).toBeFalsy();
            expect(masterTokenA.isNewerThan(masterTokenA)).toBeFalsy();
        });
    });

    it("is newer serial with different serial numbers", function() {
        var serialNumberA = 1;
        var serialNumberB = 2;
        var sequenceNumberA = 1;
        var sequenceNumberB = 2;
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterTokenB.isNewerThan(masterTokenA)).toBeTruthy();
            expect(masterTokenA.isNewerThan(masterTokenB)).toBeFalsy();
        });
    });

    it("equals trusted & untrusted", function() {
        var renewalWindow = new Date(Date.now() + 1000);
        var expiration = new Date(Date.now() + 2000);
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var hmacKey = MockPresharedAuthenticationFactory.KPH;
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);

        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterToken, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var untrustedMasterToken;
        runs(function() {
            var signature = mo.getBytes(KEY_SIGNATURE);
            ++signature[1];
            mo.put(KEY_SIGNATURE, signature);
            MasterToken.parse(ctx, mo, {
                result: function(token) { untrustedMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return untrustedMasterToken; }, "untrustedMasterToken", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterToken.equals(untrustedMasterToken)).toBeTruthy();
        });
    });

    it("equals serial number", function() {
        var serialNumberA = 1;
        var serialNumberB = 2;
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);
        var masterTokenA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterTokenA, {
                result: function(mo) {
                    MasterToken.parse(ctx, mo, {
                        result: function(token) { masterTokenA2 = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterTokenA.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA.uniqueKey()).toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenB)).toBeFalsy();
            expect(masterTokenB.equals(masterTokenA)).toBeFalsy();
            expect(masterTokenB.uniqueKey()).not.toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenA2)).toBeTruthy();
            expect(masterTokenA2.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA2.uniqueKey()).toEqual(masterTokenA.uniqueKey());
        });
    });

    it("equals sequence number", function() {
        var sequenceNumberA = 1;
        var sequenceNumberB = 2;
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);
        var masterTokenA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterTokenA, {
                result: function(mo) {
                    MasterToken.parse(ctx, mo, {
                        result: function(token) { masterTokenA2 = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterTokenA.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA.uniqueKey()).toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenB)).toBeFalsy();
            expect(masterTokenB.equals(masterTokenA)).toBeFalsy();
            expect(masterTokenB.uniqueKey()).not.toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenA2)).toBeTruthy();
            expect(masterTokenA2.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA2.uniqueKey()).toEqual(masterTokenA.uniqueKey());
        });
    });

    it("equals expiration", function() {
        var expirationA = new Date(EXPIRATION.getTime());
        var expirationB = new Date(EXPIRATION.getTime() + 10000);
        var masterTokenA, masterTokenB;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken.create(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens", MslTestConstants.TIMEOUT_CRYPTO);
        var masterTokenA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, masterTokenA, {
                result: function(mo) {
                    MasterToken.parse(ctx, mo, {
                        result: function(token) { masterTokenA2 = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterTokenA.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA.uniqueKey()).toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenB)).toBeFalsy();
            expect(masterTokenB.equals(masterTokenA)).toBeFalsy();
            expect(masterTokenB.uniqueKey()).not.toEqual(masterTokenA.uniqueKey());

            expect(masterTokenA.equals(masterTokenA2)).toBeTruthy();
            expect(masterTokenA2.equals(masterTokenA)).toBeTruthy();
            expect(masterTokenA2.uniqueKey()).toEqual(masterTokenA.uniqueKey());
        });
    });

    it("equals object", function() {
        var masterToken;
        runs(function() {
            MasterToken.create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT_CRYPTO);
        runs(function() {
            expect(masterToken.equals(null)).toBeFalsy();
            expect(masterToken.equals(IDENTITY)).toBeFalsy();
        });
    });
});
