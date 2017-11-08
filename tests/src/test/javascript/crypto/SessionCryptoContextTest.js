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

/**
 * Session crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SessionCryptoContext", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslError = require('msl-core/MslError.js');
    var SessionCryptoContext = require('msl-core/crypto/SessionCryptoContext.js');
    var MslCiphertextEnvelope = require('msl-core/crypto/MslCiphertextEnvelope.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** Key ciphertext. */
    var KEY_CIPHERTEXT = "ciphertext";
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /**
     * @param {MslContext} ctx MSL context.
	 * @param {result: function(MasterToken), error: function(Error)}
	 *        callback the callback functions that will receive the envelope
	 *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    function getTrustedMasterToken(ctx, callback) {
		var renewalWindow = new Date(Date.now() + 1000);
		var expiration = new Date(Date.now() + 2000);
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
        MasterToken.create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, signatureKey, callback);
    }
    
    /**
     * @param {MslContext} ctx MSL context.
     * @param {SecretKey} encryptionKey master token encryption key.
     * @param {SecretKey} signatureKey master token signature key.
	 * @param {result: function(MasterToken), error: function(Error)}
	 *        callback the callback functions that will receive the envelope
	 *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if the master token is constructed incorrectly.
     * @throws MslEncoderException if there is an error editing the data.
     */
    function getUntrustedMasterToken(ctx, encryptionKey, signatureKey, callback) {
		var renewalWindow = new Date(Date.now() + 1000);
		var expiration = new Date(Date.now() + 2000);
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;

        MasterToken.create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, signatureKey, {
            result: function(masterToken) {
                var mo = MslTestUtils.toMslObject(encoder, masterToken, {
                    result: function(mo) {
                        var signature = mo.getBytes("signature");
                        ++signature[1];
                        mo.put("signature", signature);
                        MasterToken.parse(ctx, mo, callback);
                    },
                    error: callback.error,
                });
            },
            error: callback.error,
        });
    }
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Random. */
    var random = new Random();
    
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
                initialized = true;
            });
        }
    });

    it("untrusted", function() {
    	var encryptionKey = MockPresharedAuthenticationFactory.KPE;
    	var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	
    	var masterToken;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(mt) { masterToken = mt; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
    	
    	runs(function() {
    		var f = function() {
    			new SessionCryptoContext(ctx, masterToken);
    		};
    		expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED));
    	});
    });

    it("encrypt/decrypt w/master token", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);
        
        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var ciphertextA, ciphertextB;
        runs(function() {
        	cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
        		result: function(c) { ciphertextA = c; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
        		result: function(c) { ciphertextB = c; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return ciphertextA && ciphertextB; }, "ciphertext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(ciphertextA).not.toBeNull();
	        expect(ciphertextA).not.toEqual(messageA);
	        expect(ciphertextB).not.toBeNull();
	        expect(ciphertextB).not.toEqual(messageB);
	        expect(ciphertextA).not.toEqual(ciphertextB);
        });
        
        var plaintextA, plaintextB;
        runs(function() {
	        cryptoContext.decrypt(ciphertextA, encoder, {
	        	result: function(p) { plaintextA = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        cryptoContext.decrypt(ciphertextB, encoder, {
	        	result: function(p) { plaintextB = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return plaintextA && plaintextB; }, "plaintext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(plaintextA).not.toBeNull();
	        expect(plaintextA).toEqual(messageA);
	        expect(plaintextB).not.toBeNull();
	        expect(plaintextB).toEqual(messageB);
        });
    });
    
    it("encrypt/decrypt w/keys", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, signatureKey);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not recevied", MslTestConstants.TIMEOUT);
    	        
        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);
        
        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var ciphertextA, ciphertextB;
        runs(function() {
        	cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
        		result: function(c) { ciphertextA = c; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
        		result: function(c) { ciphertextB = c; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return ciphertextA && ciphertextB; }, "ciphertext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(ciphertextA).not.toBeNull();
	        expect(ciphertextA).not.toEqual(messageA);
	        expect(ciphertextB).not.toBeNull();
	        expect(ciphertextB).not.toEqual(messageB);
	        expect(ciphertextA).not.toEqual(ciphertextB);
        });
        
        var plaintextA, plaintextB;
        runs(function() {
	        cryptoContext.decrypt(ciphertextA, encoder, {
	        	result: function(p) { plaintextA = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        cryptoContext.decrypt(ciphertextB, encoder, {
	        	result: function(p) { plaintextB = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return plaintextA && plaintextB; }, "plaintext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(plaintextA).not.toBeNull();
	        expect(plaintextA).toEqual(messageA);
	        expect(plaintextB).not.toBeNull();
	        expect(plaintextB).toEqual(messageB);
        });
    });

    it("invalid ciphertext", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);

    	var envelope;
    	runs(function() {
    	    var envelopeMo = encoder.parseObject(ciphertext);
    		MslCiphertextEnvelope.parse(envelopeMo, null, {
    			result: function(e) { envelope = e; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return envelope; }, "parsed envelope not received", MslTestConstants.TIMEOUT);

    	var shortEnvelope;
    	runs(function() {
	    	var ciphertext = envelope.ciphertext;
	    	++ciphertext[0];
	    	++ciphertext[ciphertext.length - 1];
	    	MslCiphertextEnvelope.create(envelope.keyId, envelope.iv, ciphertext, {
	    		result: function(e) { shortEnvelope = e; },
	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	});
    	});
    	waitsFor(function() { return shortEnvelope; }, "created envelope not received", MslTestConstants.TIMEOUT);
    	
    	var encode;
    	runs(function() {
    	    shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
    	        result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    	    });
    	});
    	waitsFor(function() { return encode; }, "encode not received", MslTestConstants.TIMEOUT);
    	
    	var exception;
    	runs(function() {
    		cryptoContext.decrypt(encode, encoder, {
    			result: function() {},
    			error: function(e) { exception = e; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
    	
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
    	});
    });

	it("insufficient ciphertext", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);
    	
    	var envelope;
    	runs(function() {
    	    var envelopeMo = encoder.parseObject(ciphertext);
	    	MslCiphertextEnvelope.parse(envelopeMo, null, {
	    		result: function(e) { envelope = e; },
	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	});
    	});
    	waitsFor(function() { return envelope; }, "parsed envelope not received", MslTestConstants.TIMEOUT);
    	
    	var shortEnvelope;
    	runs(function() {
	    	var ciphertext = envelope.ciphertext;
	
	    	var shortCiphertext = new Uint8Array(ciphertext.buffer, 0, ciphertext.length / 2);
	    	MslCiphertextEnvelope.create(envelope.keyId, envelope.iv, shortCiphertext, {
	    		result: function(e) { shortEnvelope = e; },
	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	});
    	});
    	waitsFor(function() { return shortEnvelope; }, "created envelope not received", MslTestConstants.TIMEOUT);
        
        var encode;
        runs(function() {
            shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return encode; }, "encode not received", MslTestConstants.TIMEOUT);
    	
    	var exception;
    	runs(function() {
        	cryptoContext.decrypt(encode, encoder, {
        		result: function() {},
        		error: function(e) { exception = e; }
        	});
    	});
    	waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);

    	runs(function() {
	    	var f = function() { throw exception; };
	    	expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
    	});
    });
    
    it("not an envelope", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);
    	
    	var encode;
    	runs(function() {
    	    var envelopeMo = encoder.parseObject(ciphertext);
    	    envelopeMo.remove(KEY_CIPHERTEXT);
    	    encoder.encodeObject(envelopeMo, ENCODER_FORMAT, {
    	    	result: function(x) { encode = x; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    	    });
    	});
    	waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
    	
    	var exception;
    	runs(function() {
	    	cryptoContext.decrypt(encode, encoder, {
	    		result: function() {},
	    		error: function(err) { exception = err; },
	    	});
    	});
    	waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);

    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR));
    	});
    });
    
    it("corrupt envelope", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);
    	
    	var exception;
    	runs(function() {
    		ciphertext[0] = 0;
    		cryptoContext.decrypt(ciphertext, encoder, {
    			result: function() {},
    			error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);

    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR));
    	});
    });

    it("encrypt/decrypt with null encryption key", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, signatureKey);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);

    	var messageA = new Uint8Array(32);
    	random.nextBytes(messageA);

    	var exception;
    	runs(function() {
    		cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
    			result: function() {},
    			error: function(err) { exception = err; }
    		});
    	});

    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
    	});
    });
    
    it("encrypt/decrypt with null signature key", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);
        
        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);
        
        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var ciphertextA, ciphertextB;
        runs(function() {
	        cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
	        	result: function(c) { ciphertextA = c; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	        });
	        cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
	        	result: function(c) { ciphertextB = c; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	        });
        });
        waitsFor(function() { return ciphertextA && ciphertextB; }, "ciphertext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(ciphertextA).not.toBeNull();
	        expect(ciphertextA).not.toEqual(messageA);
	        expect(ciphertextB).not.toBeNull();
	        expect(ciphertextB).not.toEqual(messageB);
	        expect(ciphertextA).not.toEqual(ciphertextB);
        });
        
        var plaintextA, plaintextB;
        runs(function() {
        	cryptoContext.decrypt(ciphertextA, encoder, {
        		result: function(p) { plaintextA = p; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.decrypt(ciphertextB, encoder, {
        		result: function(p) { plaintextB = p; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return plaintextA && plaintextB; }, "plaintext not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(plaintextA).not.toBeNull();
	        expect(plaintextA).toEqual(messageA);
	        expect(plaintextB).not.toBeNull();
	        expect(plaintextB).toEqual(messageB);
        });
    });
    
    it("encrypt/decrypt with mismatched key ID", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContextA, cryptoContextB;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				// With untrusted master tokens, there is no way of verifying the
    		    	// identity provided against the internals of the master token. So this
    		    	// test makes use of two session crypto contexts with different
    		    	// identities.
    		    	cryptoContextA = new SessionCryptoContext(ctx, masterToken, identity + "A", encryptionKey, signatureKey);
    		    	cryptoContextB = new SessionCryptoContext(ctx, masterToken, identity + "B", encryptionKey, signatureKey);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContextA && cryptoContextB; }, "crypto contexts not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);
    	
    	var plaintext;
    	runs(function() {
    		expect(ciphertext).not.toBeNull();
    		expect(ciphertext).not.toEqual(message);
    		
    		cryptoContextB.decrypt(ciphertext, encoder, {
    			result: function(p) { plaintext = p; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return plaintext; }, "plaintext not received", MslTestConstants.TIMEOUT);

    	runs(function() {
    		expect(plaintext).not.toBeNull();
    		expect(plaintext).toEqual(message);
    	});
    });

	it("encrypt/decrypt with mismatched keys", function() {
    	var identity = MockPresharedAuthenticationFactory.PSK_ESN;
    	var encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
    	var signatureKeyA = MockPresharedAuthenticationFactory.KPH;
    	var encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
    	var signatureKeyB = MockPresharedAuthenticationFactory.KPH2;
    	
    	var cryptoContextA;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKeyA, signatureKeyA, {
    			result: function(masterTokenA) {
    				cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, signatureKeyA);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContextA; }, "crypto context A not received", MslTestConstants.TIMEOUT);
    	
    	var cryptoContextB;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKeyB, signatureKeyB, {
    			result: function(masterTokenB) {
    				cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, signatureKeyB);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContextB; }, "crypto context B not received", MslTestConstants.TIMEOUT);

    	var message = new Uint8Array(32);
    	random.nextBytes(message);

    	var ciphertext;
    	runs(function() {
    		cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    			result: function(c) { ciphertext = c; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    		});
    	});
    	waitsFor(function() { return ciphertext; }, "ciphertext not received", MslTestConstants.TIMEOUT);
    	
    	var exception;
    	runs(function() {
    		cryptoContextB.decrypt(ciphertext, encoder, {
    			result: function() {},
    			error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", 300);

    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
    	});
    });
    
    it("sign/verify", function() {
    	var cryptoContext;
    	runs(function() {
    		getTrustedMasterToken(ctx, {
    			result: function(masterToken) { cryptoContext = new SessionCryptoContext(ctx, masterToken); },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not received", MslTestConstants.TIMEOUT);
        
        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);
        
        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var signatureA, signatureB;
        runs(function() {
        	cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
        		result: function(s) { signatureA = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
            cryptoContext.sign(messageB, encoder, ENCODER_FORMAT, {
            	result: function(s) { signatureB = s; },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return signatureA && signatureB; }, "signature not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(signatureA).not.toBeNull();
	        expect(signatureA.length).toBeGreaterThan(0);
	        expect(signatureA).not.toEqual(messageA);
	        expect(signatureB.length).toBeGreaterThan(0);
	        expect(signatureB).not.toEqual(signatureA);
        });
        
        var verifiedAA, verifiedBB, verifiedBA;
        runs(function() {
        	cryptoContext.verify(messageA, signatureA, encoder, {
        		result: function(v) { verifiedAA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	cryptoContext.verify(messageB, signatureB, encoder, {
        		result: function(v) { verifiedBB = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.verify(messageB, signatureA, encoder, {
        		result: function(v) { verifiedBA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(verifiedAA).toBeTruthy();
	        expect(verifiedBB).toBeTruthy();
	        expect(verifiedBA).toBeFalsy();
        });
    });
    
    it("sign/verify with mismatched contexts", function() {
    	var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
        var signatureKeyA = MockPresharedAuthenticationFactory.KPH;
        var encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
        var signatureKeyB = MockPresharedAuthenticationFactory.KPH2;

    	var cryptoContextA;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKeyA, signatureKeyA, {
    			result: function(masterTokenA) {
    				cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, signatureKeyA);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContextA; }, "crypto context A not received", MslTestConstants.TIMEOUT);
    	
    	var cryptoContextB;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKeyB, signatureKeyB, {
    			result: function(masterTokenB) {
    				cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, signatureKeyB);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContextB; }, "crypto context B not received", MslTestConstants.TIMEOUT);
        
    	var message = new Uint8Array(32);
        random.nextBytes(message);
        
        var signature;
        runs(function() {
        	cryptoContextA.sign(message, encoder, ENCODER_FORMAT, {
        		result: function(s) { signature = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return signature; }, "signature not received", MslTestConstants.TIMEOUT);
        
        var verified;
        runs(function() {
        	cryptoContextB.verify(message, signature, encoder, {
        		result: function(v) { verified = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
        runs(function() {
        	expect(verified).toBeFalsy();
        });
    });
    
    it("sign/verify with crypto context from keys", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, signatureKey);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not recevied", MslTestConstants.TIMEOUT);
    	
        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);

        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var signatureA, signatureB;
        runs(function() {
        	cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
        		result: function(s) { signatureA = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	cryptoContext.sign(messageB, encoder, ENCODER_FORMAT, {
        		result: function(s) { signatureB = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return signatureA && signatureB; }, "signature not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(signatureA).not.toBeNull();
	        expect(signatureA.length).toBeGreaterThan(0);
	        expect(signatureA).not.toEqual(messageA);
	        expect(signatureB.length).toBeGreaterThan(0);
	        expect(signatureB).not.toEqual(signatureA);
        });
        
        var verifiedAA, verifiedBB, verifiedBA;
        runs(function() {
        	cryptoContext.verify(messageA, signatureA, encoder, {
        		result: function(v) { verifiedAA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	cryptoContext.verify(messageB, signatureB, encoder, {
        		result: function(v) { verifiedBB = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.verify(messageB, signatureA, encoder, {
        		result: function(v) { verifiedBA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(verifiedAA).toBeTruthy();
	        expect(verifiedBB).toBeTruthy();
	        expect(verifiedBA).toBeFalsy();
        });
    });
    
    it("sign/verify with null encryption key", function() {
        var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, signatureKey);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not recevied", MslTestConstants.TIMEOUT);
        
        var messageA = new Uint8Array(32);
        random.nextBytes(messageA);
        
        var messageB = new Uint8Array(32);
        random.nextBytes(messageB);
        
        var signatureA, signatureB;
        runs(function() {
        	cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
        		result: function(s) { signatureA = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	cryptoContext.sign(messageB, encoder, ENCODER_FORMAT, {
        		result: function(s) { signatureB = s; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return signatureA && signatureB; }, "signature not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(signatureA).not.toBeNull();
	        expect(signatureA.length).toBeGreaterThan(0);
	        expect(signatureA).not.toEqual(messageA);
	        expect(signatureB.length).toBeGreaterThan(0);
	        expect(signatureB).not.toEqual(signatureA);
        });

        var verifiedAA, verifiedBB, verifiedBA;
        runs(function() {
        	cryptoContext.verify(messageA, signatureA, encoder, {
        		result: function(v) { verifiedAA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	cryptoContext.verify(messageB, signatureB, encoder, {
        		result: function(v) { verifiedBB = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	cryptoContext.verify(messageB, signatureA, encoder, {
        		result: function(v) { verifiedBA = v; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(verifiedAA).toBeTruthy();
	        expect(verifiedBB).toBeTruthy();
	        expect(verifiedBA).toBeFalsy();
        });
    });
    
    it("sign/verify with null signature key", function() {
    	var identity = MockPresharedAuthenticationFactory.PSK_ESN;
    	var encryptionKey = MockPresharedAuthenticationFactory.KPE;
    	var signatureKey = MockPresharedAuthenticationFactory.KPH;
    	var cryptoContext;
    	runs(function() {
    		getUntrustedMasterToken(ctx, encryptionKey, signatureKey, {
    			result: function(masterToken) {
    				cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
    			},
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return cryptoContext; }, "crypto context not recevied", MslTestConstants.TIMEOUT);
    	
    	var messageA = new Uint8Array(32);
    	random.nextBytes(messageA);
    	
    	var exception;
    	runs(function() {
    		cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
    			result: function() {},
    			error: function(err) { exception = err; },
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
    	
    	runs(function() {
    		var f = function() { throw exception; };
    		expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
    	});
    });
});
