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
 * Message output stream unit tests.
 *
 * These tests assume the MessageOutputStream does not construct the header
 * data but delegates that to the Header. Likewise for PayloadChunks. So there
 * are no checks for proper encoding.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageOutputStream", function() {
    /** Maximum number of payload chunks to generate. */
    var MAX_PAYLOAD_CHUNKS = 10;
    /** Maximum payload chunk data size in bytes. */
    var MAX_DATA_SIZE = 10 * 1024;
    /** Compressible data. */
    var COMPRESSIBLE_DATA = textEncoding$getBytes(
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me."
    );
    /** I/O operation timeout in milliseconds. */
    var TIMEOUT = 20;
    
    /** Random. */
    var random = new Random();
    /** MSL context. */
    var ctx;
    /** Destination output stream. */
    var destination = new ByteArrayOutputStream();
    /** Payload crypto context. */
    var PAYLOAD_CRYPTO_CONTEXT;
    /** Header service token crypto contexts. */
    var cryptoContexts = [];
    
    var ENTITY_AUTH_DATA;
    var MESSAGE_HEADER;
    var ERROR_HEADER;
    
    // Shortcuts.
    var HeaderData = MessageHeader$HeaderData;
    var HeaderPeerData = MessageHeader$HeaderPeerData;
    var CompressionAlgorithm = MslConstants$CompressionAlgorithm;
    var CompressionAlgorithm$getPreferredAlgorithm = MslConstants$CompressionAlgorithm$getPreferredAlgorithm;
    
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
    			ctx.getEntityAuthenticationData(null, {
    				result: function(x) { ENTITY_AUTH_DATA = x; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ENTITY_AUTH_DATA; }, "entity authentication data", 100);
    		
    		runs(function() {
	    		var headerData = new HeaderData(null, 1, null, false, false, ctx.getMessageCapabilities(), null, null, null, null, null);
	    		var peerData = new HeaderPeerData(null, null, null);
	    		MessageHeader$create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
	    			result: function(x) { MESSAGE_HEADER = x; },
	    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    		});
	    		ErrorHeader$create(ctx, ENTITY_AUTH_DATA, null, 1, MslConstants$ResponseCode.FAIL, 3, "errormsg", "usermsg", {
	    			result: function(x) { ERROR_HEADER = x; },
	    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    		});
    		});
    		waitsFor(function() { return MESSAGE_HEADER && ERROR_HEADER; }, "message header and error header", 100);
    		runs(function() {
    			PAYLOAD_CRYPTO_CONTEXT = MESSAGE_HEADER.cryptoContext;
    			initialized = true;
    		});
    	}
    });

    afterEach(function() {
    	destination = new ByteArrayOutputStream();
    });
    
    it("message header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var header = undefined, tokener;
        runs(function() {
	        mos.close(TIMEOUT, {
	        	result: function(success) {
	        		var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
	        		tokener = new ClarinetParser(mslMessage);

	        		// There should be one header.
	        		expect(tokener.more()).toBeTruthy();
	        		var first = tokener.nextValue();
	        		expect(typeof first === 'object').toBeTruthy();
	        		var headerJo = first;

	        		// The reconstructed header should be equal to the original.
	        		Header$parseHeader(ctx, headerJo, cryptoContexts, {
	        			result: function(x) { header = x; },
	        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        		});	
	        	},
	        	timeout: function() { throw new Error("timeout"); },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return header && tokener; }, "header and tokener", 100);

        var payload;
        runs(function() {
	        expect(header instanceof MessageHeader).toBeTruthy();
	        var messageHeader = header;
	        expect(messageHeader).toEqual(MESSAGE_HEADER);
	        
	        // There should be one payload with no data indicating end of message.
	        expect(tokener.more()).toBeTruthy();
	        var second = tokener.nextValue();
	        expect(typeof second === 'object').toBeTruthy();
	        var payloadJo = second;
	        
	        // Verify the payload.
	        var cryptoContext = messageHeader.cryptoContext;
	        expect(cryptoContext).not.toBeNull();
	        PayloadChunk$parse(payloadJo, cryptoContext, {
	        	result: function(x) { payload = x; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return payload; }, "payload not received", 100);
        
        runs(function() {
        	expect(payload.isEndOfMessage()).toBeTruthy();
	        expect(payload.sequenceNumber).toEqual(1);
	        expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
	        expect(payload.data.length).toEqual(0);
	        
	        // There should be nothing else.
	        expect(tokener.more()).toBeFalsy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(1);
	        expect(payloads[0]).toEqual(payload);
        });
    });
    
    it("error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, ERROR_HEADER, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var header = undefined, tokener;
        runs(function() {
        	mos.close(TIMEOUT, {
	        	result: function(success) {
		        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
		        	tokener = new ClarinetParser(mslMessage);
		
		        	// There should be one header.
		        	expect(tokener.more()).toBeTruthy();
		        	var first = tokener.nextValue();
		        	expect(typeof first === 'object').toBeTruthy();
		        	var headerJo = first;
		
		        	// The reconstructed header should be equal to the original.
		        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
		        		result: function(x) { header = x; },
		        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		        	});
	        	},
	        	timeout: function() { throw new Error("timeout"); },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return header && tokener; }, "header and tokener", 100);

        runs(function() {
        	expect(header instanceof ErrorHeader).toBeTruthy();
        	expect(header).toEqual(ERROR_HEADER);

        	// There should be no payloads.
        	expect(tokener.more()).toBeFalsy();

        	// Verify cached payloads.
        	var payloads = mos.getPayloads();
        	expect(payloads.length).toEqual(0);
        });
    });
    
    it("write with offsets", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

    	var data = new Uint8Array(32);
    	random.nextBytes(data);
    	var from = 8;
    	var length = 8;
    	var to = from + length; // exclusive
        var written = false;
        runs(function() {
        	mos.write(data, from, length, TIMEOUT, {
        		result: function(success) {
        			mos.close(TIMEOUT, {
        				result: function(success) { written = success; },
        				timeout: function() { throw new Error("timeout"); },
        				error: function(e) { throw err; }
        			});
        		},
        		timeout: function() { throw new Error("timeout"); },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return written; }, "written", 100);

        var header = undefined, tokener;
        runs(function() {
        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
        	tokener = new ClarinetParser(mslMessage);

        	// There should be one header.
        	expect(tokener.more()).toBeTruthy();
        	var first = tokener.nextValue();
        	expect(typeof first === 'object').toBeTruthy();
        	var headerJo = first;

        	// We assume the reconstructed header is equal to the original.
        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
        		result: function(x) { header = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return header && tokener; }, "header and tokener", 100);

        var payload;
        runs(function() {
        	expect(header instanceof MessageHeader).toBeTruthy();
        	var messageHeader = header;

        	// There should be one payload.
        	expect(tokener.more()).toBeTruthy();
        	var second = tokener.nextValue();
        	expect(typeof second === 'object').toBeTruthy();
        	var payloadJo = second;

        	// Verify the payload.
        	var cryptoContext = messageHeader.cryptoContext;
        	expect(cryptoContext).not.toBeNull();
        	PayloadChunk$parse(payloadJo, cryptoContext, {
        		result: function(x) { payload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return payload; }, "payload not received", 100);

        runs(function() {
	        expect(payload.isEndOfMessage()).toBeTruthy();
	        expect(payload.sequenceNumber).toEqual(1);
	        expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
	        expect(payload.data).toEqual(new Uint8Array(data.subarray(from, to)));
	        
	        // There should be nothing else.
	        expect(tokener.more()).toBeFalsy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(1);
	        expect(payloads[0]).toEqual(payload);
        });
    });
    
    it("write", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

    	var data = new Uint8Array(32);
    	random.nextBytes(data);
        var written = false;
        runs(function() {
        	mos.write(data, 0, data.length, TIMEOUT, {
        		result: function(success) {
        		    expect(success).toBeTruthy();
        			mos.close(TIMEOUT, {
        				result: function(success) { written = true; },
        				timeout: function() { throw new Error("timeout"); },
        				error: function(e) { throw err; }
        			});
        		},
        		timeout: function() { throw new Error("timeout"); },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return written; }, "written", 100);

        var header = undefined, tokener;
        runs(function() {
        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
        	tokener = new ClarinetParser(mslMessage);

        	// There should be one header.
        	expect(tokener.more()).toBeTruthy();
        	var first = tokener.nextValue();
        	expect(typeof first === 'object').toBeTruthy();
        	var headerJo = first;

        	// We assume the reconstructed header is equal to the original.
        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
        		result: function(x) { header = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return header && tokener; }, "header and tokener", 100);

        var payload;
        runs(function() {
        	expect(header instanceof MessageHeader).toBeTruthy();
        	var messageHeader = header;

        	// There should be one payload.
        	expect(tokener.more()).toBeTruthy();
        	var second = tokener.nextValue();
        	expect(typeof second === 'object').toBeTruthy();
        	var payloadJo = second;

        	// Verify the payload.
        	var cryptoContext = messageHeader.cryptoContext;
        	expect(cryptoContext).not.toBeNull();
        	PayloadChunk$parse(payloadJo, cryptoContext, {
        		result: function(x) { payload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return payload; }, "payload not received", 100);

        runs(function() {
	        expect(payload.isEndOfMessage()).toBeTruthy();
	        expect(payload.sequenceNumber).toEqual(1);
	        expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
	        expect(payload.data).toEqual(data);
	        
	        // There should be nothing else.
	        expect(tokener.more()).toBeFalsy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(1);
	        expect(payloads[0]).toEqual(payload);
        });
    });
    
    it("write with compression", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var first = Arrays$copyOf(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length);
        var secondA = Arrays$copyOf(first, 0, 2 * first.length);
        secondA.set(first, first.length);
		var secondB = Arrays$copyOf(first, 0, 3 * first.length);
		secondB.set(first, first.length);
		secondB.set(first, 2 * first.length);
	    
        var written = false;
        runs(function() {
	        // Write the first payload.
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(first, 0, first.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "first", 100);
        
        runs(function() {
            written = false;
            // Changing the compressed value should result in a new payload.
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(secondA, 0, secondA.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "secondA", 100);
        
        runs(function() {
            written = false;
            // Setting the compressed value to the same should maintain the same
            // payload.
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(secondB, 0, secondB.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "secondB", 100);
        
        var closed = false;
        runs(function() {
            // Changing the compressed value should flush the second payload.
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    // Closing should create a final payload.
                    mos.close(TIMEOUT, {
                        result: function(success) { closed = success; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", 100);
        
        var messageHeader = undefined, payloadJos;
        runs(function() {
	        // Grab the JSON objects.
	        var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
	        var tokener = new ClarinetParser(mslMessage);
	        var headerJo = tokener.nextValue();
	        payloadJos = [];
	        while (tokener.more())
	        	payloadJos.push(tokener.nextValue());

	        // Verify the number and contents of the payloads.
	        Header$parseHeader(ctx, headerJo, cryptoContexts, {
	        	result: function(x) { messageHeader = x; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return messageHeader && payloadJos; }, "messageHeader and payloadJos", 100);

        var firstPayload = undefined, secondPayload = undefined, thirdPayload;
        runs(function() {
        	var cryptoContext = messageHeader.cryptoContext;
        	expect(payloadJos.length).toEqual(3);
        	PayloadChunk$parse(payloadJos[0], cryptoContext, {
        		result: function(x) { firstPayload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	PayloadChunk$parse(payloadJos[1], cryptoContext, {
        		result: function(x) { secondPayload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	PayloadChunk$parse(payloadJos[2], cryptoContext, {
        		result: function(x) { thirdPayload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return firstPayload && secondPayload && thirdPayload; }, "payloads", 100);
        
        runs(function() {
        	expect(firstPayload.data).toEqual(first);
        	expect(Arrays$copyOf(secondPayload.data, 0, secondA.length)).toEqual(secondA);
        	expect(Arrays$copyOf(secondPayload.data, secondA.length, secondB.length)).toEqual(secondB);
        	expect(thirdPayload.data.length).toEqual(0);
	        expect(thirdPayload.isEndOfMessage()).toBeTruthy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(payloadJos.length);
	        expect(payloads[0]).toEqual(firstPayload);
	        expect(payloads[1]).toEqual(secondPayload);
	        expect(payloads[2]).toEqual(thirdPayload);
        });
    });
    
    it("flush", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var first = new Uint8Array(10);
        random.nextBytes(first);
        var secondA = new Uint8Array(20);
        random.nextBytes(secondA);
		var secondB = new Uint8Array(30);
		random.nextBytes(secondB);
	    
        var written;
        runs(function() {
	    	// Write the first payload.
	    	mos.write(first, 0, first.length, TIMEOUT, {
	    		result: function() {
	    			// Flushing should result in a new payload.
	    	    	mos.flush(TIMEOUT, {
	    	    		result: function() {
	    	    	    	mos.write(secondA, 0, secondA.length, TIMEOUT, {
	    	    	    		result: function() {
	    	    	    			// Not flushing should maintain the same payload.
	    	    	    	    	mos.write(secondB, 0, secondB.length, TIMEOUT, {
	    	    	    	    		result: function() {
	    	    	    	    			// Flush the second payload.
	    	    	    	    	    	mos.flush(TIMEOUT, {
	    	    	    	    	    		result: function() {
	    	    	    	    	    	    	// Closing should create a final payload.
	    	    	    	    	    	    	mos.close(TIMEOUT, {
	    	    	    	    	    	    		result: function(success) { written = success; },
	    	    	    	    	    	    		timeout: function() { throw new Error("timeout"); },
	    	    	    	    	    	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	    	    	    	    	});	
	    	    	    	    	    		},
	    	    	    	    	    		timeout: function() { throw new Error("timeout"); },
	    	    	    	    	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	    	    	    	});
	    	    	    	    		},
	    	    	    	    		timeout: function() { throw new Error("timeout"); },
	    	    	    	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	    	    	});
	    	    	    		},
	    	    	    		timeout: function() { throw new Error("timeout"); },
	    	    	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	    	});
	    	    		},
	    	    		timeout: function() { throw new Error("timeout"); },
	    	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	    	    	});
	    		},
	    		timeout: function() { throw new Error("timeout"); },
	    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	});
        });
        waitsFor(function() { return written; }, "written", 100);
        
        var messageHeader = undefined, payloadJos;
        runs(function() {
        	// Grab the JSON objects.
        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
        	var tokener = new ClarinetParser(mslMessage);
        	var headerJo = tokener.nextValue();
        	payloadJos = [];
        	while (tokener.more())
        		payloadJos.push(tokener.nextValue());

        	// Verify the number and contents of the payloads.
        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
        		result: function(x) { messageHeader = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return messageHeader && payloadJos; }, "messageHeader and payloadJos", 100);
        
        var firstPayload = undefined, secondPayload = undefined, thirdPayload;
        runs(function() {
        	var cryptoContext = messageHeader.cryptoContext;
        	expect(payloadJos.length).toEqual(3);
        	PayloadChunk$parse(payloadJos[0], cryptoContext, {
        		result: function(x) { firstPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$parse(payloadJos[1], cryptoContext, {
                result: function(x) { secondPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk$parse(payloadJos[2], cryptoContext, {
                result: function(x) { thirdPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstPayload && secondPayload && thirdPayload; }, "payloads", 100);
        
        runs(function() {
	        expect(Arrays$copyOf(secondPayload.data, 0, secondA.length)).toEqual(secondA);
	        expect(Arrays$copyOf(secondPayload.data, secondA.length, secondB.length)).toEqual(secondB);
	        expect(firstPayload.data).toEqual(first);
	
	        expect(thirdPayload.data.length).toEqual(0);
	        expect(thirdPayload.isEndOfMessage()).toBeTruthy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(payloadJos.length);
	        expect(payloads[0]).toEqual(firstPayload);
	        expect(payloads[1]).toEqual(secondPayload);
	        expect(payloads[2]).toEqual(thirdPayload);
        });
    });
    
    it("write to an error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, ERROR_HEADER, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var exception;
        runs(function() {
        	var data = new Uint8Array(0);
            mos.write(data, 0, data.length, TIMEOUT, {
            	result: function() {},
            	timeout: function() { throw new Error("timeout"); },
            	error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            mos.close(TIMEOUT, {
            	result: function() {},
            	timeout: function() { throw new Error("timeout"); },
            	error: function() {}
            });
        	var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("write to a handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(null, 1, null, false, true, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader$create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", 100);
        
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, messageHeader, messageHeader.cryptoContext, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var exception;
        runs(function() {
            var data = new Uint8Array(0);
            mos.write(data, 0, data.length, TIMEOUT, {
                result: function() {},
                timeout: function() { throw new Error("timeout"); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            mos.close(TIMEOUT, {
                result: function() {},
                timeout: function() { throw new Error("timeout"); },
                error: function() {}
            });
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("closed", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var exception;
        runs(function() {
        	mos.close(TIMEOUT, {
        		result: function() {
        			var data = new Uint8Array(0);
        			mos.write(data, 0, data.length, TIMEOUT, {
        				result: function() {},
        				timeout: function() { throw new Error("timeout"); },
        				error: function(e) { exception = e; }
        			});
        		},
        		timeout: function() { throw new Error("timeout"); },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslIoException());
        });
    });
    
    it("flush an error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, ERROR_HEADER, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var flushed = false;
        runs(function() {
            // No data so this should be a no-op.
            mos.flush(TIMEOUT, {
            	result: function(success) {
            		flushed = success;
            		mos.close(TIMEOUT, {
            			result: function(success) { flushed &= success; },
            			timeout: function() { throw new Error("timeout"); },
            			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            		});
            	},
            	timeout: function() { throw new Error("timeout"); },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return flushed; }, "flushed", 100);
    });
    
    it("stop caching", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var first = new Uint8Array(10);
        random.nextBytes(first);
        var second = new Uint8Array(20);
        random.nextBytes(second);
        
        var wroteFirst = false;
        runs(function() {
            // Write the first payload.
            mos.write(first, 0, first.length, TIMEOUT, {
                result: function() {
                    mos.flush(TIMEOUT, {
                        result: function() {
                            wroteFirst = true;
                        },
                        timeout: function() { throw new Error("timeout"); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { throw new Error("timeout"); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return wroteFirst; }, "wroteFirst", 100);
        
        var wroteSecond = false;
        runs(function() {
            // Verify one payload.
            var onePayload = mos.getPayloads();
            expect(onePayload.length).toEqual(1);
            
            // Stop caching.
            mos.stopCaching();
            var zeroPayload = mos.getPayloads();
            expect(zeroPayload.length).toEqual(0);
            
            // Write the second payload.
            mos.write(second, 0, second.length, TIMEOUT, {
                result: function() {
                    mos.flush(TIMEOUT, {
                        result: function() {
                            wroteSecond = true;
                        },
                        timeout: function() { throw new Error("timeout"); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { throw new Error("timeout"); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return wroteSecond; }, "wroteSecond", 100);
        
        runs(function() {
            // Verify zero payloads.
            var twoPayload = mos.getPayloads();
            expect(twoPayload.length).toEqual(0);
            
            // Close.
            mos.close(TIMEOUT, {
                result: function() {},
                timeout: function() { throw new Error("timeout"); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
    });
    
    it("call close multiple times", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var closed = false;
        runs(function() {
        	mos.close(TIMEOUT, {
        		result: function(success) {
        			closed = success;
        			mos.close(TIMEOUT, {
        				result: function(success) { closed &= success; },
        				timeout: function() { throw new Error("timeout"); },
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		timeout: function() { throw new Error("timeout"); },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return closed; }, "closed", 100);
        
        var header = undefined, tokener;
        runs(function() {
        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
        	tokener = new ClarinetParser(mslMessage);

        	// There should be one header.
        	expect(tokener.more()).toBeTruthy();
        	var first = tokener.nextValue();
        	expect(typeof first === 'object').toBeTruthy();
        	var headerJo = first;

        	// We assume the reconstructed header is equal to the original.
        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
        		result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header && tokener; }, "header and tokener", 100);

        var payload;
        runs(function() {
        	expect(header instanceof MessageHeader).toBeTruthy();
        	var messageHeader = header;

        	// There should be one payload with no data indicating end of message.
        	expect(tokener.more()).toBeTruthy();
        	var second = tokener.nextValue();
        	expect(typeof second === 'object').toBeTruthy();
        	var payloadJo = second;

        	// Verify the payload.
        	var cryptoContext = messageHeader.cryptoContext;
        	expect(cryptoContext).not.toBeNull();
        	PayloadChunk$parse(payloadJo, cryptoContext, {
        		result: function(x) { payload = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return payload; }, "payload not received", 100);
        
        runs(function() {
	        expect(payload.isEndOfMessage()).toBeTruthy();
	        expect(payload.sequenceNumber).toEqual(1);
	        expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
	        expect(payload.data.length).toEqual(0);
	        
	        // There should be nothing else.
	        expect(tokener.more()).toBeFalsy();
	        
	        // Verify cached payloads.
	        var payloads = mos.getPayloads();
	        expect(payloads.length).toEqual(1);
	        expect(payloads[0]).toEqual(payload);
        });
    });
    
    it("stress write", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var noCompression = false;
        runs(function() {
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) { noCompression = success; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return noCompression; }, "no compression", 100);

        // This may take a while to finish.
    	var message = new ByteArrayOutputStream();
        var written = false;
        runs(function() {
        	// Generate some payload chunks, keeping track of what we're writing.
        	var count = random.nextInt(MAX_PAYLOAD_CHUNKS) + 1;
        	function randomWrite(callback) {
        		InterruptibleExecutor(callback, function() {
        			if (count-- == 0) {
        				mos.close(TIMEOUT, callback);
        				return;
        			}

        			function writeData(callback) {
        				var data = new Uint8Array(MAX_DATA_SIZE);
        				random.nextBytes(data);
        				mos.write(data, 0, data.length, TIMEOUT, {
        					result: function(success) {
        						message.write(data, 0, data.length, TIMEOUT, callback);
        					},
        					timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
        					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        				});
        			}
        			function setCompressionAlgo(callback) {
        				mos.setCompressionAlgorithm(random.nextBoolean() ? CompressionAlgorithm.LZW : null, TIMEOUT, {
        					result: function(success) {
        						writeData(callback);
        					},
        					timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
        					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        				});
        			}
        			function flush(callback) {
        				if (random.nextBoolean()) {
        					mos.flush(TIMEOUT, {
        						result: function(success) {
        							setCompressionAlgo(callback);
        						},
        						timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        					});
        				} else {
        					setCompressionAlgo(callback);
        				}
        			}
        			flush({
        				result: function(success) { randomWrite(callback); },
        				timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		});
        	}
        	randomWrite({
        		result: function(success) { written = success; },
        		timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return written; }, "written", 3000);

        var header = undefined, payloadJos;
        runs(function() {
        	// The destination should have received the message header followed by
        	// one or more payload chunks.
        	var mslMessage = textEncoding$getString(destination.toByteArray(), MslConstants$DEFAULT_CHARSET);
        	var tokener = new ClarinetParser(mslMessage);
        	var headerJo = tokener.nextValue();
        	payloadJos = [];
        	while (tokener.more())
        		payloadJos.push(tokener.nextValue());

        	Header$parseHeader(ctx, headerJo, cryptoContexts, {
        		result: function(x) { header = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return header && payloadJos; }, "header and payloadJos", 100);
        
        // This may take a while to finish.
        var parsedPayloads = [];
        runs(function() {
        	expect(header instanceof MessageHeader).toBeTruthy();
        	var cryptoContext = header.cryptoContext;
        	
        	function parse(index) {
                PayloadChunk$parse(payloadJos[index], cryptoContext, {
                    result: function(x) { parsedPayloads[index] = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
        	}
        	for (var i = 0; i < payloadJos.length; ++i)
        	    parse(i);
        });
        waitsFor(function() { return parsedPayloads.length == payloadJos.length; }, "payloads", 3000);
        
        runs(function() {
        	// Verify payloads, cached payloads, and aggregate data.
        	var sequenceNumber = 1;
        	var payloads = mos.getPayloads();
        	expect(payloads.length).toEqual(payloadJos.length);
        	var data = new ByteArrayOutputStream();
        	var index = 0;
        	function verifyPayload() {
        		if (index == parsedPayloads.length) {
                	expect(data.toByteArray()).toEqual(message.toByteArray());
        			return;
        		}
        		
        		var payload = parsedPayloads[index];
	            expect(payload.sequenceNumber).toEqual(sequenceNumber++);
	            expect(payload.messageId).toEqual(header.messageId);
	            expect(payload.isEndOfMessage()).toEqual(index == payloadJos.length - 1);
	            expect(payloads[index]).toEqual(payload);
	            data.write(payload.data, 0, payload.data.length, TIMEOUT, {
	            	result: function(success) {
	            		++index;
	            		verifyPayload();
	            	},
	            	timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	}
        	verifyPayload();
        });
    });

    it("no context compression algorithms", function() {
        var ctx;
        runs(function() {
            MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", 100);

        var mos;
        runs(function() {
            ctx.setMessageCapabilities(null);

            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw === false; }, "lzw", 100);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 100);
        
        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toBeNull();
        });
    });
    
    it("no request compression algorithms", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(null, 1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader$create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", 100);
        
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, messageHeader, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);

        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw === false; }, "lzw", 100);
        
        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 100);
        
        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toBeNull();
        });
    });
    
    it("best compression algorithm", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 100);
        
        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            
            var capabilities = ctx.getMessageCapabilities();
            var algos = capabilities.compressionAlgorithms;
            var bestAlgo = CompressionAlgorithm$getPreferredAlgorithm(algos);
            expect(payloads[0].compressionAlgo).toEqual(bestAlgo);
        });
    });
    
    it("set compression algorithm", function() {
        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw; }, "lzw", 300);

        runs(function() {
            written = false;
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function(success) { written = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 100);
        
        var closed;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function(success) { closed = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", 100);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toEqual(CompressionAlgorithm.LZW);
        });
    });
    
    it("one supported compression algorithm", function() {
        var algos = [ CompressionAlgorithm.LZW ];
        var capabilities = new MessageCapabilities(algos, null);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(null, 1, null, false, false, capabilities, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader$create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", 100);

        var mos;
        runs(function() {
            MessageOutputStream$create(ctx, destination, MslConstants$DEFAULT_CHARSET, messageHeader, PAYLOAD_CRYPTO_CONTEXT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", 100);
        
        var gzip;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP, TIMEOUT, {
                result: function(success) { gzip = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return gzip === false; }, "gzip", 100);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 100);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toEqual(CompressionAlgorithm.LZW);
        });
    });
});
