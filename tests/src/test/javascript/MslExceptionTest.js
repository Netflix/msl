/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
describe("MslException", function() {
    var EmailPasswordAuthenticationData = require('msl-core/userauth/EmailPasswordAuthenticationData.js');
    var MslException = require('msl-core/MslException.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslError = require('msl-core/MslError.js');
    var MslConstants = require('msl-core/MslConstants.js');

    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
    
    /**
     * @return {UserAuthenticationData} dummy user authentication data.
     */
    function getUserAuthenticationData() {
        return new EmailPasswordAuthenticationData("email", "password");
    }

    /** MSL context. */
    var ctx;

    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "static initialization", 900);
        }
    });

	it("error as expected", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message);
		expect(e.cause).toBeUndefined();
		expect(e.messageId).toBeUndefined();
	});

	it("error details as expected", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR, "details");
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).toBeUndefined();
		expect(e.messageId).toBeUndefined();
	});

	it("error details and cause as expected", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR, "details", new Error("cause"));
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).not.toBeNull();
		expect(e.cause.message).toBe("cause");
	});

	it("message ID can be set", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e.messageId).toBeUndefined();
		e.messageId = 1;
		expect(e.messageId).toEqual(1);
	});

	it("message ID can be set via setMessageId()", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e.messageId).toBeUndefined();
		e.setMessageId(1);
		expect(e.messageId).toEqual(1);
	});

	it("name is correct", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e.name).toEqual("MslException");
	});

	it("toString() is correct", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR, "details", new Error("cause"));
		expect(e.toString()).toEqual('MslException: ' + MslError.MSL_PARSE_ERROR.message + ' [details]');
	});

	it("exception properties are not writable", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR, "details", new Error("cause"));
		e.message = "x";
		e.error = "x";
		e.cause = "x";
		e.name = "x";
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).not.toBeNull();
		expect(e.cause.message).toBe("cause");
	});

	it("instanceof MslException", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e instanceof MslException).toBeTruthy();
	});

	it("instanceof Error", function() {
		var e = new MslException(MslError.MSL_PARSE_ERROR);
		expect(e instanceof Error).toBeTruthy();
	});

	it("Error not instanceof MslException", function() {
		var e = new Error("msg");
		expect(e instanceof MslException).toBeFalsy();
	});

    it("set master token", function() {
        var e = new MslException(MslError.MSL_PARSE_ERROR);
        expect(e.masterToken).toBeNull();
        expect(e.entityAuthenticationData).toBeNull();

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", 100);

        var entityAuthData;
        runs(function() {
            ctx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData", 100);

        runs(function() {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            expect(e.masterToken).toEqual(masterToken);
            expect(e.entityAuthenticationData).toBeNull();
        });
    });

    it("set entity authentication data", function() {
        var e = new MslException(MslError.MSL_PARSE_ERROR);
        expect(e.masterToken).toBeNull();
        expect(e.entityAuthenticationData).toBeNull();

        var entityAuthData;
        runs(function() {
            ctx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData", 100);

        runs(function() {
            e.setEntityAuthenticationData(entityAuthData);
            expect(e.masterToken).toBeNull();
            expect(e.entityAuthenticationData).toEqual(entityAuthData);
        });
    });

    it("set user ID token", function() {
        var e = new MslException(MslError.MSL_PARSE_ERROR);
        expect(e.userIdToken).toBeNull();
        expect(e.userAuthenticationData).toBeNull();

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", 100);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", 100);

        runs(function() {
            var userAuthData = getUserAuthenticationData();
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            expect(e.userIdToken).toEqual(userIdToken);
            // XXX: this 'expect' should fail since the userIdToken
            //      and the userAuthenticationData are set separately
            // expect(e.userAuthenticationData).toBeNull();
        });
    });

    it("set user authentication data", function() {
        var e = new MslException(MslError.MSL_PARSE_ERROR);
        expect(e.userIdToken).toBeNull();
        expect(e.userAuthenticationData).toBeNull();
        var userAuthData = getUserAuthenticationData();
        e.setUserAuthenticationData(userAuthData);
        expect(e.userIdToken).toBeNull();
        expect(e.userAuthenticationData).toEqual(userAuthData);
    });

    it("set message ID", function() {
        var e = new MslException(MslError.MSL_PARSE_ERROR);
        expect(e.messageId).toBeUndefined();
        e.messageId = 1;
        expect(e.messageId).toEqual(1);
    });

    it("negative message ID", function() {
        var f = function() {
            var e = new MslException(MslError.MSL_PARSE_ERROR);
            e.messageId = -1;
        };
        expect(f).toThrow(new RangeError());
    });

    it("too large message ID", function() {
        var f = function() {
            var e = new MslException(MslError.MSL_PARSE_ERROR);
            e.messageId = MslConstants.MAX_LONG_VALUE + 2;
        };
        expect(f).toThrow(new RangeError());
    });
});
