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
 * Master token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MasterToken", function() {
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
    /** JSON key sequence number. */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** JSON key serial number. */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key session data. */
    var KEY_SESSIONDATA = "sessiondata";
    
    // sessiondata
    /** JSON key issuer data. */
    var KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    var KEY_IDENTITY = "identity";
    /** JSON key symmetric encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key encryption algorithm. */
    var KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /** JSON key symmetric HMAC key. */
    var KEY_HMAC_KEY = "hmackey";
    /** JSON key signature key. */
    var KEY_SIGNATURE_KEY = "signaturekey";
    /** JSON key signature algorithm. */
    var KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";
    
    var RENEWAL_WINDOW = new Date(Date.now() + 120000);
    var EXPIRATION = new Date(Date.now() + 180000);
    var SEQUENCE_NUMBER = 1;
    var SERIAL_NUMBER = 42;
    var IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    var ENCRYPTION_KEY;
    var SIGNATURE_KEY;
    
    var ISSUER_DATA = { "issuerid": 17 };
    
    /** MSL context. */
    var ctx;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 500);
            runs(function() {
                // These keys won't exist until after the factory is instantiated.
                ENCRYPTION_KEY = MockPresharedAuthenticationFactory.KPE;
                SIGNATURE_KEY = MockPresharedAuthenticationFactory.KPH;
            });
            waitsFor(function() { return ENCRYPTION_KEY && SIGNATURE_KEY; }, "keys", 500);
            runs(function() { initialized = true; });
        }
    });

    function incrementSequenceNumber(seqNo, amount) {
        if (seqNo - MslConstants$MAX_LONG_VALUE + amount <= 0)
            return seqNo + amount;
        return seqNo - MslConstants$MAX_LONG_VALUE - 1 + amount;
    }
    
    function decrementSequenceNumber(seqNo, amount) {
        if (seqNo - amount >= 0)
        	return seqNo - amount;
        return MslConstants$MAX_LONG_VALUE - amount - 1 + seqNo;
    }
    
    it("ctors", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var jsonString;
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
	        jsonString = JSON.stringify(masterToken);
	        expect(jsonString).not.toBeNull();
        });
        
        var joMasterToken;
        runs(function() {
        	var jo = JSON.parse(jsonString);
            MasterToken$parse(ctx, jo, {
                result: function(token) { joMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        runs(function() {
	        expect(joMasterToken.isDecrypted()).toEqual(masterToken.isDecrypted());
	        expect(joMasterToken.isVerified()).toEqual(masterToken.isVerified());
	        expect(joMasterToken.isRenewable(null)).toEqual(masterToken.isRenewable(null));
	        expect(joMasterToken.isExpired(null)).toEqual(masterToken.isExpired(null));
	        expect(joMasterToken.isNewerThan(masterToken)).toBeFalsy();
	        expect(masterToken.isNewerThan(joMasterToken)).toBeFalsy();
	        expect(joMasterToken.encryptionKey.toByteArray()).toEqual(masterToken.encryptionKey.toByteArray());
	        expect(joMasterToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joMasterToken.signatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
	        expect(joMasterToken.identity).toEqual(masterToken.identity);
	        expect(joMasterToken.issuerData).toEqual(masterToken.issuerData);
	        expect(joMasterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joMasterToken.sequenceNumber).toEqual(masterToken.sequenceNumber);
	        expect(joMasterToken.serialNumber).toEqual(masterToken.serialNumber);
	        var joJsonString = JSON.stringify(joMasterToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("negative sequence number ctor", function() {
    	var exception;
    	runs(function() {
	        var sequenceNumber = -1;
	        MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("too large sequence number ctor", function() {
    	var exception;
    	runs(function() {
	        var sequenceNumber = MslConstants$MAX_LONG_VALUE + 2;
	        MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslInternalException());
    	});
    });

    it("negative serial number ctor", function() {
    	var exception;
    	runs(function() {
	        var serialNumber = -1;
	        MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslInternalException());
    	});
    });

    it("too large serial number ctor", function() {
    	var exception;
    	runs(function() {
    		var serialNumber = MslConstants$MAX_LONG_VALUE + 2;
	        MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 500);
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
	        MasterToken$create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
	            result: function() {},
	            error: function(err) { exception = err; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("inconsistent expiration JSON", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_EXPIRATION] = (Date.now() / MILLISECONDS_PER_SECOND) - 1;
	        tokendataJo[KEY_RENEWAL_WINDOW] = Date.now() / MILLISECONDS_PER_SECOND;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL));
    	});
    });
    
    it("null issuer data", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, null, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        runs(function() {
        	expect(masterToken.issuerData).toBeNull();
        });
        
        var joMasterToken;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            MasterToken$parse(ctx, jo, {
                result: function(token) { joMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        runs(function() {
        	expect(joMasterToken.issuerData).toBeUndefined();
        });
    });
    
    it("missing tokendata", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	
	        expect(jo[KEY_TOKENDATA]).not.toBeNull();
	        delete jo[KEY_TOKENDATA];
	
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    	});
    });
    
    it("invalid tokendata", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        ++tokendata[0];
	        jo[KEY_TOKENDATA] = base64$encode(tokendata);
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.NONE));
    	});
    });
    
    it("missing signature", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        expect(jo[KEY_SIGNATURE]).not.toBeNull();
	        delete jo[KEY_SIGNATURE];
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    	});
    });
    
    it("missing renewal window", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_RENEWAL_WINDOW]).not.toBeNull();
	        delete tokendataJo[KEY_RENEWAL_WINDOW];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid renewal window", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_RENEWAL_WINDOW] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("missing expiration", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_EXPIRATION]).not.toBeNull();
	        delete tokendataJo[KEY_EXPIRATION];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid expiration", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_EXPIRATION] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("missing sequence number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_SEQUENCE_NUMBER]).not.toBeNull();
	        delete tokendataJo[KEY_SEQUENCE_NUMBER];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid sequence number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SEQUENCE_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("negative sequence number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SEQUENCE_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE));
    	});
    });
    
    it("too large sequence number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SEQUENCE_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE));
    	});
    });
    
    it("missing serial number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_SERIAL_NUMBER]).not.toBeNull();
	        delete tokendataJo[KEY_SERIAL_NUMBER];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    
    it("invalid serial number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);

        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("negative serial number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
    	});
    });
    
    it("too large serial number", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SERIAL_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
    	});
    });
    
    it("missing session data", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect(tokendataJo[KEY_SESSIONDATA]).not.toBeNull();
	        delete tokendataJo[KEY_SESSIONDATA];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        MasterToken$parse(ctx, jo, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid session data", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_SESSIONDATA] = "";
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	        	result: function(signature) {
	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        MasterToken$parse(ctx, jo, {
	    	        	result: function() {},
	    	        	error: function(err) { exception = err; },
	    	        });	
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SESSIONDATA_MISSING));
    	});
    });
    
    it("empty session data", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        var ciphertext = new Uint8Array(0);
	        tokendataJo[KEY_SESSIONDATA] = base64$encode(ciphertext);
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	        	result: function(signature) {
	    	        jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        MasterToken$parse(ctx, jo, {
	    	        	result: function() {},
	    	        	error: function(err) { exception = err; },
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslException(MslError.MASTERTOKEN_SESSIONDATA_MISSING));
    	});
    });
    
    it("corrupt session data", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        // This is testing session data that is verified but corrupt.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var sessiondata = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        ++sessiondata[sessiondata.length-1];
	        tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        cryptoContext.sign(modifiedTokendata, {
	            result: function(signature) {
	                jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	                jo[KEY_SIGNATURE] = base64$encode(signature);

	                MasterToken$parse(ctx, jo, {
	                    result: function() {},
	    	        	error: function(err) { exception = err; },
	    	        });	        		
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslCryptoException(MslError.NONE));
    	});
    });
    
    it("not verified", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);

        var jsonString;
        var joMasterToken;
        runs(function() {
	        jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        ++signature[0];
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
            MasterToken$parse(ctx, jo, {
                result: function(token) { joMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joMasterToken; }, "joMasterToken not received", 500);
        
        runs(function() {
	        expect(joMasterToken.isDecrypted()).toBeFalsy();
	        expect(joMasterToken.isVerified()).toBeFalsy();
	        expect(joMasterToken.isRenewable(null)).not.toEqual(masterToken.isRenewable(null));
	        expect(joMasterToken.isExpired(null)).toEqual(masterToken.isExpired(null));
	        expect(joMasterToken.isNewerThan(masterToken)).toBeFalsy();
	        expect(masterToken.isNewerThan(joMasterToken)).toBeFalsy();
	        expect(joMasterToken.encryptionKey).toBeNull();
	        expect(joMasterToken.expiration.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.expiration.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joMasterToken.signatureKey).toBeNull();
	        expect(joMasterToken.identity).toBeNull();
	        expect(joMasterToken.issuerData).toBeNull();
	        expect(joMasterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND).toEqual(masterToken.renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
	        expect(joMasterToken.sequenceNumber).toEqual(masterToken.sequenceNumber);
	        expect(joMasterToken.serialNumber).toEqual(masterToken.serialNumber);
	        var joJsonString = JSON.stringify(joMasterToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).not.toEqual(jsonString);
        });
    });
    
    it("invalid issuer data", function() {
    	var masterToken;
    	runs(function() {
    		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
    			result: function(token) { masterToken = token; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return masterToken; }, "masterToken", 500);
    	
    	var exception;
    	runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
	    	        sessiondataJo[KEY_ISSUER_DATA] = "x";
	    	        var json = JSON.stringify(sessiondataJo);
	    	        plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	    	        tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	    	        jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
	    	    	    	        });	    	    	        		
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
    	waitsFor(function() { return exception; }, "exception not received", 500);
	    runs(function() {
	        var f = function() { throw exception; };
	        expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
	    });
    });
    
    it("missing identity", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
	    	        expect(sessiondataJo[KEY_IDENTITY]).not.toBeNull();
	    	        delete sessiondataJo[KEY_IDENTITY];
	    	        var json = JSON.stringify(sessiondataJo);
	    	        plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	    	        tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	    	        jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
	    	    	    	        });
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
    	});
    });
    
    it("missing encryption key", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
	    	        expect(sessiondataJo[KEY_ENCRYPTION_KEY]).not.toBeNull();
	    	        delete sessiondataJo[KEY_ENCRYPTION_KEY];
	    	        var json = JSON.stringify(sessiondataJo);
	    	        plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	        		tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
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
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
    	});
    });

    it("invalid encryption key", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
	    	        sessiondataJo[KEY_ENCRYPTION_KEY] = "";
	    	        var json = JSON.stringify(sessiondataJo);
	    	        plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	        		tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
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
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR));
    	});
    });
    
    it("missing encryption algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var joMasterToken;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    expect(sessiondataJo[KEY_ENCRYPTION_ALGORITHM]).not.toBeNull();
                    delete sessiondataJo[KEY_ENCRYPTION_ALGORITHM];
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function(x) { joMasterToken = x; },
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
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        
        runs(function() {
            // Confirm default algorithm.
            var joEncryptionKey = joMasterToken.encryptionKey;
            expect(WebCryptoAlgorithm.AES_CBC['name']).toEqual(joEncryptionKey.algorithm['name']);
        });
    });
    
    it("invalid encryption algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    sessiondataJo[KEY_ENCRYPTION_ALGORITHM] = "x";
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function() {},
                                        error: function(e) { exception = e; }
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
        waitsFor(function() { return exception; }, "exception not received", 500);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM));
        });
    });
    
    it("missing HMAC key", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var joMasterToken;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    expect(sessiondataJo[KEY_HMAC_KEY]).not.toBeNull();
                    delete sessiondataJo[KEY_HMAC_KEY];
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function(x) { joMasterToken = x; },
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
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        
        runs(function() {
            // Confirm signature key.
            var joSignatureKey = joMasterToken.signatureKey;
            expect(joSignatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
        });
    });
    
    it("missing signature key", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var joMasterToken;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    expect(sessiondataJo[KEY_SIGNATURE_KEY]).not.toBeNull();
                    delete sessiondataJo[KEY_SIGNATURE_KEY];
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function(x) { joMasterToken = x; },
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
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        
        runs(function() {
            // Confirm signature key.
            var joSignatureKey = joMasterToken.signatureKey;
            expect(joSignatureKey.toByteArray()).toEqual(masterToken.signatureKey.toByteArray());
        });
    });
    
    it("missing signature algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var joMasterToken;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    expect(sessiondataJo[KEY_SIGNATURE_ALGORITHM]).not.toBeNull();
                    delete sessiondataJo[KEY_SIGNATURE_ALGORITHM];
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function(x) { joMasterToken = x; },
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
        waitsFor(function() { return joMasterToken; }, "joMasterToken not received", 500);
        
        runs(function() {
            // Confirm default algorithm.
            var joSignatureKey = joMasterToken.signatureKey;
            expect(WebCryptoAlgorithm.HMAC_SHA256['name']).toEqual(joSignatureKey.algorithm['name']);
            expect(joSignatureKey.algorithm['hash']).toBeTruthy();
            expect(WebCryptoAlgorithm.HMAC_SHA256['hash']['name']).toEqual(joSignatureKey.algorithm['hash']['name']);
        });
    });
    
    it("invalid signature algorithm", function() {
        var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
            var jsonString = JSON.stringify(masterToken);
            var jo = JSON.parse(jsonString);
            
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Before modifying the session data we need to decrypt it.
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
                    
                    // After modifying the session data we need to encrypt it.
                    sessiondataJo[KEY_SIGNATURE_ALGORITHM] = "x";
                    var json = JSON.stringify(sessiondataJo);
                    plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(sessiondata) {
                            tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
                            
                            // The tokendata must be signed otherwise the session data will not be
                            // processed.
                            var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
                            cryptoContext.sign(modifiedTokendata, {
                                result: function(signature) {
                                    jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                                    jo[KEY_SIGNATURE] = base64$encode(signature);
                                    
                                    MasterToken$parse(ctx, jo, {
                                        result: function() {},
                                        error: function(e) { exception = e; }
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
        waitsFor(function() { return exception; }, "exception not received", 500);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM));
        });
    });
    
    it("missing HMAC and signature key", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
                    expect(sessiondataJo[KEY_HMAC_KEY]).not.toBeNull();
                    delete sessiondataJo[KEY_HMAC_KEY];
	    	        expect(sessiondataJo[KEY_SIGNATURE_KEY]).not.toBeNull();
	    	        delete sessiondataJo[KEY_SIGNATURE_KEY];
	    	        var json = JSON.stringify(sessiondataJo);
	    	        var plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	        		tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
	    	    	    	        });	
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR));
    	});
    });
    
    it("invalid HMAC and signature key", function() {
    	var masterToken;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(masterToken);
	        var jo = JSON.parse(jsonString);
	        
	        var cryptoContext = ctx.getMslCryptoContext();
	        
	        // Before modifying the session data we need to decrypt it.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var ciphertext = base64$decode(tokendataJo[KEY_SESSIONDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var sessiondataJo = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the session data we need to encrypt it.
                    sessiondataJo[KEY_HMAC_KEY] = "";
	    	        sessiondataJo[KEY_SIGNATURE_KEY] = "";
	    	        var json = JSON.stringify(sessiondataJo);
	    	        plaintext = textEncoding$getBytes(json, MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(plaintext, {
	    	        	result: function(sessiondata) {
	    	        		tokendataJo[KEY_SESSIONDATA] = base64$encode(sessiondata);
	    	    	        
	    	    	        // The tokendata must be signed otherwise the session data will not be
	    	    	        // processed.
	    	    	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	    	    	        cryptoContext.sign(modifiedTokendata, {
	    	    	        	result: function(signature) {
	    	    	        		jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	    	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	    	    	        
	    	    	    	        MasterToken$parse(ctx, jo, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; }
	    	    	    	        });	    	        		
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });	
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 500);
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
            MasterToken$create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
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
            MasterToken$create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
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
            MasterToken$create(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
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
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 500);
        runs(function() {
        	expect(masterTokenB.isNewerThan(masterTokenA)).toBeTruthy();
        	expect(masterTokenA.isNewerThan(masterTokenB)).toBeFalsy();
        	expect(masterTokenA.isNewerThan(masterTokenA)).toBeFalsy();
        });
    });
    
    it("is newer than with different sequence numbers and wraparound", function() {
        // Anything within 128 is newer.
        for (var seqNo = MslConstants$MAX_LONG_VALUE - 127; seqNo <= MslConstants$MAX_LONG_VALUE && seqNo != 0; seqNo = incrementSequenceNumber(seqNo, 1)) {
        	// Copy seqNo because we need a local variable for the runs
        	// functions.
    		var zero = seqNo;
        	var minus1 = decrementSequenceNumber(zero, 1);
        	var plus1 = incrementSequenceNumber(zero, 1);
        	var plus127 = incrementSequenceNumber(zero, 127); 
        	var plus128 = incrementSequenceNumber(zero, 128);

        	var masterToken;
        	var minus1MasterToken = undefined, plus1MasterToken;
        	var plus127MasterToken = undefined, plus128MasterToken;
        	runs(function() {
        		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, zero, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
        			result: function(x) { masterToken = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, minus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
        			result: function(x) { minus1MasterToken = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, plus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
        			result: function(x) { plus1MasterToken = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, plus127, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
        			result: function(x) { plus127MasterToken = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        		MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, plus128, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
        			result: function(x) { plus128MasterToken = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return masterToken && minus1MasterToken && plus1MasterToken && plus127MasterToken && plus128MasterToken; }, "master tokens", 500);

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
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 1000);
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
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 500);
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
            MasterToken$create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        
        var untrustedMasterToken;
        runs(function() {
            var json = JSON.stringify(masterToken);
            var jo = JSON.parse(json);
            var signature = base64$decode(jo["signature"]);
            ++signature[1];
            jo["signature"] = base64$encode(signature);
            MasterToken$parse(ctx, jo, {
                result: function(token) { untrustedMasterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return untrustedMasterToken; }, "untrustedMasterToken not received", 500);
        runs(function() {
        	expect(masterToken.equals(untrustedMasterToken)).toBeTruthy();
        });
    });
    
    it("equals serial number", function() {
        var serialNumberA = 1;
        var serialNumberB = 2;
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 500);
        var masterTokenA2;
        runs(function() {
            MasterToken$parse(ctx, JSON.parse(JSON.stringify(masterTokenA)), {
                result: function(token) { masterTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", 500);
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
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 500);
        var masterTokenA2;
        runs(function() {
            MasterToken$parse(ctx, JSON.parse(JSON.stringify(masterTokenA)), {
                result: function(token) { masterTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", 500);
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
        var masterTokenA = undefined, masterTokenB;
        runs(function() {
            MasterToken$create(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterToken$create(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 500);
        var masterTokenA2;
        runs(function() {
            MasterToken$parse(ctx, JSON.parse(JSON.stringify(masterTokenA)), {
                result: function(token) { masterTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenA2; }, "master token parsed", 500);
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
            MasterToken$create(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY, {
                result: function(token) { masterToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", 500);
        runs(function() {
	        expect(masterToken.equals(null)).toBeFalsy();
	        expect(masterToken.equals(IDENTITY)).toBeFalsy();
        });
    });
});
