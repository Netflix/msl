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
describe("MslCryptoException", function() {
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    
	it("error as expected", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message);
		expect(e.cause).toBeUndefined();
		expect(e.messageId).toBeUndefined();
	});
	
	it("error details as expected", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR, "details");
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).toBeUndefined();
		expect(e.messageId).toBeUndefined();
	});
	
	it("error details and cause as expected", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR, "details", new Error("cause"));
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).not.toBeNull();
		expect(e.cause.message).toBe("cause");
	});
	
	it("message ID can be set", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		e.xmessageId = 1;
		expect(e.xmessageId).toEqual(1);
	});
	
	it("name is correct", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		expect(e.name).toEqual("MslCryptoException");
	});
	
	it("exception properties are not writable", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR, "details", new Error("cause"));
		e.message = "x";
		e.error = "x";
		e.cause = "x";
		e.name = "x";
		expect(e.error).toBe(MslError.MSL_PARSE_ERROR);
		expect(e.message).toEqual(MslError.MSL_PARSE_ERROR.message + " [details]");
		expect(e.cause).not.toBeNull();
		expect(e.cause.message).toBe("cause");
	});
	
	it("instanceof MslCryptoException", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		expect(e instanceof MslCryptoException).toBeTruthy();
	});
	
	it("instanceof MslException", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		expect(e instanceof MslException).toBeTruthy();
	});
	
	it("instanceof Error", function() {
		var e = new MslCryptoException(MslError.MSL_PARSE_ERROR);
		expect(e instanceof Error).toBeTruthy(); 
	});
	
	it("Error not instanceof MslCryptoException", function() {
		var e = new Error("msg");
		expect(e instanceof MslCryptoException).toBeFalsy();		
	});
});