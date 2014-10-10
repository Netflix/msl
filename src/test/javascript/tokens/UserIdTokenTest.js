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
 * User ID token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UserIdToken", function() {
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;
    
    /** JSON key token data. */
    var KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    var KEY_SIGNATURE = "signature";
    
    // tokendata
    /** JSON key renewal window timestamp. */
    var KEY_RENEWAL_WINDOW = "renewalwindow";
    /** JSON key expiration timestamp. */
    var KEY_EXPIRATION = "expiration";
    /** JSON key master token serial number. */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key token user identification data. */
    var KEY_USERDATA = "userdata";
    
    // userdata
    /** JSON key issuer data. */
    var KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    var KEY_IDENTITY = "identity";
    
    /** MSL context. */
    var ctx;
    
    var RENEWAL_WINDOW = new Date(Date.now() + 120000);
    var EXPIRATION = new Date(Date.now() + 180000);
    var MASTER_TOKEN;
    var SERIAL_NUMBER = 42;
    var ISSUER_DATA = { issuerid: 17 };
    var USER = MockEmailPasswordAuthenticationFactory.USER;
    
    var initialized = false;
    beforeEach(function() {
    	if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
    		runs(function() {
    			MslTestUtils.getMasterToken(ctx, 1, 1, {
    				result: function(token) { MASTER_TOKEN = token; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return MASTER_TOKEN; }, "master token not received", 100);
    		runs(function() { initialized = true; });
    	}
    });
    
    it("ctors", function() {
        var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var jsonString;
        runs(function() {
	        expect(userIdToken.isDecrypted()).toBeTruthy();
	        expect(userIdToken.isVerified()).toBeTruthy();
	        expect(userIdToken.isRenewable()).toBeFalsy();
	        expect(userIdToken.isExpired()).toBeFalsy();
	        expect(userIdToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
	        expect(userIdToken.issuerData).toEqual(ISSUER_DATA);
	        expect(userIdToken.user).toEqual(USER);
	        expect(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND));
	        expect(userIdToken.mtSerialNumber).toEqual(MASTER_TOKEN.serialNumber);
	        expect(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(Math.floor(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND));
	        expect(userIdToken.serialNumber).toEqual(SERIAL_NUMBER);
	        jsonString = JSON.stringify(userIdToken);
	        expect(jsonString).not.toBeNull();
        });
        
        var joUserIdToken;
        runs(function() {
            var jo = JSON.parse(jsonString);
            UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
                result: function(token) { joUserIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joUserIdToken; }, "joUserIdToken not received", 100);
        
        runs(function() {
	        expect(joUserIdToken.isDecrypted()).toEqual(userIdToken.isDecrypted());
	        expect(joUserIdToken.isVerified()).toEqual(userIdToken.isVerified());
	        expect(joUserIdToken.isRenewable()).toEqual(userIdToken.isRenewable());
	        expect(joUserIdToken.isExpired()).toEqual(userIdToken.isExpired());
	        expect(joUserIdToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
	        expect(joUserIdToken.issuerData).toEqual(userIdToken.issuerData);
	        expect(joUserIdToken.user).toEqual(userIdToken.user);
	        expect(joUserIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joUserIdToken.mtSerialNumber).toEqual(userIdToken.mtSerialNumber);
	        expect(joUserIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joUserIdToken.serialNumber).toEqual(userIdToken.serialNumber);
	        var joJsonString = JSON.stringify(joUserIdToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("negative serial number ctor", function() {
    	var serialNumber = -1;
    	
    	var exception;
    	runs(function() {
    		UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER, {
    		    result: function() {},
    		    error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("too large serial number ctor", function() {
    	var serialNumber = MslConstants$MAX_LONG_VALUE + 2;

    	var exception;
    	runs(function() {
    		UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER, {
    			result: function() {},
    			error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("null master token", function() {
    	var exception;
    	runs(function() {
    		UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, null, SERIAL_NUMBER, ISSUER_DATA, USER, {
    		    result: function() {},
    		    error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("master token mismtached", function() {
    	var masterToken = undefined, joMasterToken;
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
    	waitsFor(function() { return masterToken && joMasterToken; }, "master token not received", 100);
    	
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
	        
        var exception;
        runs(function() {
	        UserIdToken$parse(ctx, JSON.parse(JSON.stringify(userIdToken)), joMasterToken, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
		});
		waitsFor(function() { return exception; }, "exception not received", 100);
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
    	waitsFor(function() { return masterToken; }, "master token not received", 100);
    	
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
	        
        var exception;
        runs(function() {
	        UserIdToken$parse(ctx, JSON.parse(JSON.stringify(userIdToken)), null, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
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
	        UserIdToken$create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("inconsistent expiration json", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_EXPIRATION] = (Date.now() / MILLISECONDS_PER_SECOND) - 1;
	        tokendataJo[KEY_RENEWAL_WINDOW] = Date.now() / MILLISECONDS_PER_SECOND;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL));
    	});
    });
    
    it("missing tokendata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	        
	        expect(jo[KEY_TOKENDATA]).not.toBeNull();
	        delete jo[KEY_TOKENDATA];
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    	});
    });
    
    it("invalid tokendata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        ++tokendata[0];
	        jo[KEY_TOKENDATA] = base64$encode(tokendata);
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.NONE));
	    });
    });
    
    it("missing signature", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	        
	        expect(jo[KEY_SIGNATURE]).not.toBeNull();
	        delete jo[KEY_SIGNATURE];
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
	    });
    });
    
    it("missing renewal window", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_RENEWAL_WINDOW]).not.toBeNull();
	        delete tokendataJo[KEY_RENEWAL_WINDOW];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("invalid renewal window", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_RENEWAL_WINDOW] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("missing expiration", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_EXPIRATION]).not.toBeNull();
	        delete tokendataJo[KEY_EXPIRATION];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("invalid expiration", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_EXPIRATION] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("missing serial number", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_SERIAL_NUMBER]).not.toBeNull();
	        delete tokendataJo[KEY_SERIAL_NUMBER];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("invalid serial number", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("negative serial number ctor", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
	    });
    });
    
    it("too large serial number ctor", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
	    });
    });
    
    it("missing master token serial number", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER]).not.toBeNull();
	        delete tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("invalid master token serial number", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("negative master token serial number ctor", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
	    });
    });
    
    it("too large master token serial number ctor", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
	    });
    });
    
    it("missing userdata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_USERDATA]).not.toBeNull();
	        delete tokendataJo[KEY_USERDATA];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR));
	    });
    });
    
    it("invalid userdata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_USERDATA] = "";
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	        	result: function(signature) {
	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	    	            result: function() {},
	    	            error: function(err) { exception = err; },
	    	        });	
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_USERDATA_MISSING));
	    });
    });
    
    it("empty userdata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	
	        var cryptoContext = ctx.getMslCryptoContext();
	        var ciphertext = new Uint8Array(0);
	        tokendataJo[KEY_USERDATA] = base64$encode(ciphertext);
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	        	result: function(signature) {
	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	    	            result: function() {},
	    	            error: function(err) { exception = err; },
	    	        });	
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.USERIDTOKEN_USERDATA_MISSING));
    	});
    });
    
    it("corrupt userdata", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);
	
	        // This is testing user data that is verified but corrupt.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var userdata = base64$decode(tokendataJo[KEY_USERDATA]);
	        ++userdata[userdata.length-1];
	        tokendataJo[KEY_USERDATA] = base64$encode(userdata);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	        	result: function(signature) {
	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	    	            result: function() {},
	    	            error: function(err) { exception = err; },
	    	        });	
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslCryptoException(MslError.NONE));
    	});
    });
    
    it("invalid user", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);

	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the user data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_USERDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var userdataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	        		
	        		// After modifying the user data we need to encrypt it.
	        		userdataJo[KEY_IDENTITY] = {};
	        		cryptoContext.encrypt(textEncoding$getBytes(JSON.stringify(userdataJo, MslConstants$DEFAULT_CHARSET)), {
	        			result: function(userdata) {
	        				tokendataJo[KEY_USERDATA] = base64$encode(userdata);
	        				
	        				// The tokendata must be signed otherwise the user data will not be
	        				// processed.
	        				var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        				cryptoContext.sign(modifiedTokendata, {
	        		        	result: function(signature) {
	        		        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	        		    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        		    	        
	        		    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	        		    	            result: function() {},
	        		    	            error: function(err) { exception = err; },
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
        waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
    	});
    });
    
    it("empty user", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);

	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the user data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_USERDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var userdataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	        		
	        		// After modifying the user data we need to encrypt it.
	        		userdataJo[KEY_IDENTITY] = "";
	        		cryptoContext.encrypt(textEncoding$getBytes(JSON.stringify(userdataJo, MslConstants$DEFAULT_CHARSET)), {
	        			result: function(userdata) {
	        				tokendataJo[KEY_USERDATA] = base64$encode(userdata);
	        				
	        				// The tokendata must be signed otherwise the user data will not be
	        				// processed.
	        				var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        				cryptoContext.sign(modifiedTokendata, {
	        		        	result: function(signature) {
	        		        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	        		    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        		    	        
	        		    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	        		    	            result: function() {},
	        		    	            error: function(err) { exception = err; },
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
        waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID));
    	});
    });
    
    it("missing user", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);

	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the user data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_USERDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var userdataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	        		
	        		// After modifying the user data we need to encrypt it.
	        		delete userdataJo[KEY_IDENTITY];
	        		cryptoContext.encrypt(textEncoding$getBytes(JSON.stringify(userdataJo, MslConstants$DEFAULT_CHARSET)), {
	        			result: function(userdata) {
	        				tokendataJo[KEY_USERDATA] = base64$encode(userdata);
	        				
	        				// The tokendata must be signed otherwise the user data will not be
	        				// processed.
	        				var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        				cryptoContext.sign(modifiedTokendata, {
	        		        	result: function(signature) {
	        		        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	        		    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        		    	        
	        		    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	        		    	            result: function() {},
	        		    	            error: function(err) { exception = err; },
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
        waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid issuer data", function() {
    	var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(userIdToken);
	        var jo = JSON.parse(jsonString);

	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the user data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_USERDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var userdataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	        		
	        		// After modifying the user data we need to encrypt it.
	        		userdataJo[KEY_ISSUER_DATA] = "x";
	        		cryptoContext.encrypt(textEncoding$getBytes(JSON.stringify(userdataJo, MslConstants$DEFAULT_CHARSET)), {
	        			result: function(userdata) {
	        				tokendataJo[KEY_USERDATA] = base64$encode(userdata);
	        				
	        				// The tokendata must be signed otherwise the user data will not be
	        				// processed.
	        				var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        				cryptoContext.sign(modifiedTokendata, {
	        		        	result: function(signature) {
	        		        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	        		    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        		    	        
	        		    	        UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
	        		    	            result: function() {},
	        		    	            error: function(err) { exception = err; },
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
        waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR));
    	});
    });

    it("not verified", function() {
        var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        
        var jsonString = undefined, joUserIdToken;
        runs(function() {
            jsonString = JSON.stringify(userIdToken);
            var jo = JSON.parse(jsonString);

            var signature = base64$decode(jo[KEY_SIGNATURE]);
            ++signature[0];
            jo[KEY_SIGNATURE] = base64$encode(signature);

            UserIdToken$parse(ctx, jo, MASTER_TOKEN, {
                result: function(token) { joUserIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joUserIdToken; }, "joUserIdToken not received", 100);
        runs(function() {
	        expect(joUserIdToken.isDecrypted()).toBeFalsy();
	        expect(joUserIdToken.isVerified()).toBeFalsy();
	        expect(joUserIdToken.isRenewable()).toEqual(userIdToken.isRenewable());
	        expect(joUserIdToken.isExpired()).toEqual(userIdToken.isExpired());
	        expect(joUserIdToken.isBoundTo(MASTER_TOKEN)).toEqual(userIdToken.isBoundTo(MASTER_TOKEN));
	        expect(joUserIdToken.user).toBeNull();
	        expect(joUserIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joUserIdToken.mtSerialNumber).toEqual(userIdToken.mtSerialNumber);
	        expect(joUserIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(userIdToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joUserIdToken.serialNumber).toEqual(userIdToken.serialNumber);
	        var joJsonString = JSON.stringify(joUserIdToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).not.toEqual(jsonString);
        });
    });

    it("is renewable", function() {
        var renewalWindow = new Date();
        var expiration = new Date(Date.now() + 10000);
        var userIdToken;
        runs(function() {
            UserIdToken$create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        runs(function() {
            var now = new Date();
	        expect(userIdToken.isRenewable()).toBeTruthy();
            expect(userIdToken.isRenewable(now)).toBeTruthy();
            expect(userIdToken.isExpired()).toBeFalsy();
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
            UserIdToken$create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        runs(function() {
            var now = new Date();
	        expect(userIdToken.isRenewable()).toBeTruthy();
            expect(userIdToken.isRenewable(now)).toBeTruthy();
            expect(userIdToken.isExpired()).toBeTruthy();
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
            UserIdToken$create(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        runs(function() {
            var now = new Date();
	        expect(userIdToken.isRenewable()).toBeFalsy();
            expect(userIdToken.isRenewable(now)).toBeFalsy();
            expect(userIdToken.isExpired()).toBeFalsy();
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
        var masterTokenA = undefined, masterTokenB;
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
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
        
        var userIdTokenA = undefined, userIdTokenB;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", 100);
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
        var userIdTokenA = undefined, userIdTokenB;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberA, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberB, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", 100);
        var userIdTokenA2;
        runs(function() {
            UserIdToken$parse(ctx, JSON.parse(JSON.stringify(userIdTokenA)), MASTER_TOKEN, {
                result: function(token) { userIdTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA2; }, "user ID token parsed", 100);
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
        var masterTokenA = undefined, masterTokenB;
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
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
        
        var userIdTokenA = undefined, userIdTokenB;
        runs(function() {
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", 100);
        
        var userIdTokenA2;
        runs(function() {
            UserIdToken$parse(ctx, JSON.parse(JSON.stringify(userIdTokenA)), masterTokenA, {
                result: function(token) { userIdTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdTokenA2; }, "user ID token parsed", 100);
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
            UserIdToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER, {
                result: function(token) { userIdToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", 100);
        runs(function() {
	        expect(userIdToken.equals(null)).toBeFalsy();
	        expect(userIdToken.equals(RENEWAL_WINDOW)).toBeFalsy();
        });
    });
});
