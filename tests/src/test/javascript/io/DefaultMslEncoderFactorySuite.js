/**
 * Copyright (c) 2015-2018 Netflix, Inc.  All rights reserved.
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
 * MSL encoder factory tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("DefaultMslEncoderFactory", function() {
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var DefaultMslEncoderFactory = require('msl-core/io/DefaultMslEncoderFactory.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var ByteArrayOutputStream = require('msl-core/io/ByteArrayOutputStream.js');
    var MessageHeader = require('msl-core/msg/MessageHeader.js');
    var MessageOutputStream = require('msl-core/msg/MessageOutputStream.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var MslEncoderException = require('msl-core/io/MslEncoderException.js');
    var ByteArrayInputStream = require('msl-core/io/ByteArrayInputStream.js');
    var Header = require('msl-core/msg/Header.js');
    var PayloadChunk = require('msl-core/msg/PayloadChunk.js');
    var Base64 = require('msl-core/util/Base64.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** Maximum number of object fields or array elements. */
    var MAX_NUM_ELEMENTS = 20;
    /** MSL object base key name. */
    var MSL_OBJECT_KEY = "KEY";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Random. */
    var random;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            
            runs(function() {
                encoder = new DefaultMslEncoderFactory();
                random = ctx.getRandom();
                initialized = true;
            });
        }
    });

    /**
     * @return {string} a random type.
     */
    function getRandomType() {
        var i = random.nextInt(8);
        switch (i) {
            case 0:
                return "boolean";
            case 1:
                return "Uint8Array";
            case 2:
                return "double";
            case 3:
                return "integer";
            case 4:
                return "MslArray";
            case 5:
                return "MslObject";
            case 6:
                return "long";
            default:
                return "string";
        }
    }

    /**
     * @param {?string} type the type. May be {@code null}.
     * @return {?} a randomly generated object of the specified type or
     *         {@code null} if the type is {@code null}.
     */
    function createTypedValue(type) {
        if ("boolean" == type)
            return random.nextBoolean();
        if ("Uint8Array" == type) {
            var b = new Uint8Array(random.nextInt(10));
            random.nextBytes(b);
            return b;
        }
        if ("double" == type)
            return random.nextDouble();
        if ("integer" == type)
            return random.nextInt();
        if ("MslArray" == type) {
            var ma = encoder.createArray();
            var maInnerType = getRandomType();
            ma.put(-1, createTypedValue(maInnerType));
            return ma;
        }
        if ("MslObject" == type) {
            var mo = encoder.createObject();
            var moInnerType = getRandomType();
            mo.put(MSL_OBJECT_KEY, createTypedValue(moInnerType));
            return mo;
        }
        if ("long" == type)
            return random.nextLong();
        if ("string" == type)
            return "STRING";
        return null;
    }
    
    /**
     * @return {{type: string, value: ?}} a randomly generated object of a random type.
     */
    function createRandomValue() {
        var type = getRandomType();
        return { type: type, value: createTypedValue(type) };
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the getter method that explicitly
     * matches the expected type. For type {@code null} the untyped getter
     * method is used.
     * 
     * @param {string} key MSL object key.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslObject} mo the MSL object.
     * @return {?} the MSL object's value.
     * @throws MslEncoderException if the value type is not equal to the
     *         expected type.
     */
    function getTypedField(key, type, mo) {
        if ("boolean" == type)
            return mo.getBoolean(key);
        if ("Uint8Array" == type)
            return mo.getBytes(key);
        if ("double" == type)
            return mo.getDouble(key);
        if ("integer" == type)
            return mo.getInt(key);
        if ("MslArray" == type)
            return mo.getMslArray(key);
        if ("MslObject" == type)
            return mo.getMslObject(key, encoder);
        if ("long" == type)
            return mo.getLong(key);
        if ("string" == type)
            return mo.getString(key);
        return mo.get(key);
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param {string} key MSL object key.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslObject} mo the MSL object.
     * @return {?} the MSL object's value.
     */
    function optTypedField(key, type, mo) {
        if ("boolean" == type)
            return mo.optBoolean(key);
        if ("Uint8Array" == type)
            return mo.optBytes(key);
        if ("double" == type)
            return mo.optDouble(key);
        if ("integer" == type)
            return mo.optInt(key);
        if ("MslArray" == type)
            return mo.optMslArray(key);
        if ("MslObject" == type)
            return mo.optMslObject(key, encoder);
        if ("long" == type)
            return mo.optLong(key);
        if ("string" == type)
            return mo.optString(key);
        return mo.opt(key);
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param {string} key MSL object key.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslObject} mo the MSL object.
     * @return {?} the MSL object's value.
     */
    function optDefaultTypedField(key, type, mo) {
        if ("boolean" == type)
            return mo.optBoolean(key, false);
        if ("Uint8Array" == type)
            return mo.optBytes(key, new Uint8Array(0));
        if ("double" == type)
            return mo.optDouble(key, Number.NaN);
        if ("integer" == type)
            return mo.optInt(key, 0);
        if ("MslArray" == type)
            return mo.optMslArray(key);
        if ("MslObject" == type)
            return mo.optMslObject(key, encoder);
        if ("long" == type)
            return mo.optLong(key, 0);
        if ("string" == type)
            return mo.optString(key, "");
        return mo.opt(key);
    }
    
    /**
     * Put a key/value pair into the MSL object. The value will be added using
     * the put method that explicitly matches the specified type. For type
     * {@code null} the untyped put method is used.
     * 
     * @param {string} key MSL object key.
     * @param {?string} type the specified type. May be {@code null}.
     * @param {?} value the value.
     * @param {MslObject} mo the MSL object.
     */
    function putTypedField(key, type, value, mo) {
        if ("boolean" == type)
            mo.putBoolean(key, value);
        if ("Uint8Array" == type)
            mo.putBytes(key, value);
        if ("double" == type)
            mo.putDouble(key, value);
        if ("integer" == type)
            mo.putInt(key, value);
        if ("MslArray" == type)
            mo.putCollection(key, (value != null) ? value.getCollection() : null);
        if ("MslObject" == type)
            mo.putMap(key, (value != null) ? value.getMap() : null);
        if ("long" == type)
            mo.putLong(key, value);
        if ("string" == type)
            mo.putString(key, value);
        mo.put(key, value);
    }
    
    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the getter method that explicitly
     * matches the expected type. For type {@code null} the untyped getter
     * method is used.
     * 
     * @param {number} index MSL array index.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslArray} ma the MSL array.
     * @return {?} the MSL array's element.
     * @throws MslEncoderException if the value type is not equal to the
     *         expected type.
     */
    function getTypedElement(index, type, ma) {
        if ("boolean" == type)
            return ma.getBoolean(index);
        if ("Uint8Array" == type)
            return ma.getBytes(index);
        if ("double" == type)
            return ma.getDouble(index);
        if ("integer" == type)
            return ma.getInt(index);
        if ("MslArray" == type)
            return ma.getMslArray(index);
        if ("MslObject" == type)
            return ma.getMslObject(index, encoder);
        if ("long" == type)
            return ma.getLong(index);
        if ("string" == type)
            return ma.getString(index);
        return ma.get(index);
    }

    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param {number} index MSL array index.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslArray} ma the MSL array.
     * @return the MSL array's element.
     */
    function optTypedElement(index, type, ma) {
        if ("boolean" == type)
            return ma.optBoolean(index);
        if ("Uint8Array" == type)
            return ma.optBytes(index);
        if ("double" == type)
            return ma.optDouble(index);
        if ("integer" == type)
            return ma.optInt(index);
        if ("MslArray" == type)
            return ma.optMslArray(index);
        if ("MslObject" == type)
            return ma.optMslObject(index, encoder);
        if ("long" == type)
            return ma.optLong(index);
        if ("string" == type)
            return ma.optString(index);
        return ma.opt(index);
    }

    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param {number} index MSL array index.
     * @param {?string} type the expected type. May be {@code null}.
     * @param {MslArray} ma the MSL array.
     * @return the MSL array's element.
     */
    function optDefaultTypedElement(index, type, ma) {
        if ("boolean" == type)
            return ma.optBoolean(index, false);
        if ("Uint8Array" == type)
            return ma.optBytes(index, new Uint8Array(0));
        if ("double" == type)
            return ma.optDouble(index, Number.NaN);
        if ("integer" == type)
            return ma.optInt(index, 0);
        if ("MslArray" == type)
            return ma.optMslArray(index);
        if ("MslObject" == type)
            return ma.optMslObject(index, encoder);
        if ("long" == type)
            return ma.optLong(index, 0);
        if ("string" == type)
            return ma.optString(index, "");
        return ma.opt(index);
    }

    /**
     * Put a value into the MSL array at the specified index. The value will be
     * added using the put method that explicitly matches the specified type.
     * For type {@code null} the untyped put method is used.
     * 
     * @param key MSL object key.
     * @param {?string} type the specified type. May be {@code null}.
     * @param {?} value the value.
     * @param {MslObject} mo the MSL object.
     */
    function putTypedElement(index, type, value, ma) {
        if ("boolean" == type)
            ma.putBoolean(index, value);
        if ("Uint8Array" == type)
            ma.putBytes(index, value);
        if ("double" == type)
            ma.putDouble(index, value);
        if ("integer" == type)
            ma.putInt(index, value);
        if ("MslArray" == type)
            ma.putCollection(index, (value != null) ? value.getCollection() : null);
        if ("MslObject" == type)
            ma.putMap(index, (value != null) ? value.getMap() : null);
        if ("long" == type)
            ma.putLong(index, value);
        if ("string" == type)
            ma.putString(index, value);
        ma.put(index, value);
    }
    
    /** Tokenizer unit tests. */
    describe("Tokenizer", function() {
        /** Example payloads. */
        var PAYLOADS = [
            TextEncoding.getBytes("payload1", MslConstants.DEFAULT_CHARSET),
            TextEncoding.getBytes("payload2", MslConstants.DEFAULT_CHARSET),
        ];
        
        var jsonMessageData, unsupportedMessageData;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                // JSON encoder format.
                var jsonCaps = new MessageCapabilities(null, null, [ MslEncoderFormat.JSON ]);

                // Create MSL message.
                var destination = new ByteArrayOutputStream();
                var peerData = new MessageHeader.HeaderPeerData(null, null, null);
                var entityAuthData;
                runs(function() {
                    ctx.getEntityAuthenticationData(null, {
                        result: function(x) { entityAuthData = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                });
                waitsFor(function() { return entityAuthData; }, "entityAuthData", MslTestConstants.TIMEOUT);
                
                var jsonMessageHeader;
                runs(function() {
                    // Create JSON version.
                    var jsonHeaderData = new MessageHeader.HeaderData(1, null, false, false, jsonCaps, null, null, null, null, null);
                    MessageHeader.create(ctx, entityAuthData, null, jsonHeaderData, peerData, {
                        result: function(x) { jsonMessageHeader = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                });
                waitsFor(function() { return jsonMessageHeader; }, "jsonMessageHeader", MslTestConstants.TIMEOUT);
                
                var jsonMos;
                runs(function() {
                    var jsonCryptoContext = jsonMessageHeader.cryptoContext;
                    MessageOutputStream.create(ctx, destination, jsonMessageHeader, jsonCryptoContext, null, -1, {
                        result: function(x) { jsonMos = x; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                });
                waitsFor(function() { return jsonMos; }, "jsonMos", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    function writePayload(index) {
                        if (index >= PAYLOADS.length) {
                            closeMos();
                            return;
                        }
                        
                        var payload = PAYLOADS[index];
                        jsonMos.write(payload, 0, payload.length, -1, {
                            result: function(count) {
                                jsonMos.flush(-1, {
                                    result: function(flushed) {
                                        writePayload(index + 1);
                                    },
                                    timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                                });
                            },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                        });
                    }
                    writePayload(0);
                    
                    function closeMos() {
                        jsonMos.close(-1, {
                            result: function(closed) {
                                // JSON.
                                jsonMessageData = destination.toByteArray();
                                
                                // Unsupported.
                                unsupportedMessageData = Arrays.copyOf(jsonMessageData, 0, jsonMessageData.length);
                                unsupportedMessageData[0] = '1';
                                
                                initialized = true;
                            },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                        });
                    }
                });
                waitsFor(function() { return initialized; }, "initialized", MslTestConstants.TIMEOUT);
            }
        });
        
        parameterize("Parameterized", function data() {
            return [
                [ MslEncoderFormat.JSON, null ],
                [ null, new MslEncoderException() ],
            ];
        },
        /**
         * Create a new MSL encoder factory test instance with the specified
         * encoding format and provided message data.
         * 
         * @param {?MslEncoderFormat} format MSL encoding format.
         * @param {?Error} exceptionClass expected exception class.
         */
        function(format, expectedException) {
            /**
             * Encoded message.
             * @type {Uint8Array}
             */
            var messageData;
            beforeEach(function() {
                if (format == MslEncoderFormat.JSON)
                    messageData = jsonMessageData;
                else if (format == null)
                    messageData = unsupportedMessageData;
                else
                    throw new Error("Unidentified message format.");
            });
            
            it("detect tokenizer", function() {
                var tokenizer, exception;
                runs(function() {
                    // Create the tokenizer.
                    var source = new ByteArrayInputStream(messageData);
                    encoder.createTokenizer(source, null, -1, {
                        result: function(x) { tokenizer = x; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { exception = e; },
                    });
                });
                waitsFor(function() { return tokenizer || exception; }, "tokenizer or exception", MslTestConstants.TIMEOUT);
    
                runs(function() {
                    if (expectedException) {
                        expect(function() { throw exception; }).toThrow(expectedException);
                        return;
                    } else if (exception) {
                        expect(function() { throw exception; }).not.toThrow();
                        return;
                    }
    
                    var objects;
                    runs(function() {
                        expect(tokenizer).not.toBeNull();
                    
                        // Pull data off the tokenizer.
                        var tokens = [];
                        function f() {
                            tokenizer.more(-1, {
                                result: function(success) {
                                    if (!success) {
                                        objects = tokens;
                                        return;
                                    }
                                    tokenizer.nextObject(-1, {
                                        result: function(object) {
                                            expect(object).not.toBeNull();
                                            tokens.push(object);
                                            f();
                                        },
                                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                                    });
                                },
                                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                            });
                        }
                        f();
                    });
                    waitsFor(function() { return objects; }, "objects", MslTestConstants.TIMEOUT);
                    
                    var nextObject;
                    runs(function() {
                        // +1 for the header, +1 for the EOM payload.
                        expect(objects.length).toEqual(PAYLOADS.length + 2);
                        tokenizer.nextObject(-1, {
                            result: function(object) { nextObject = object; },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                        });
                    });
                    waitsFor(function() { return nextObject !== undefined; }, "nextObject", MslTestConstants.TIMEOUT);
                    
                    var header;
                    runs(function() {
                        expect(nextObject).toBeNull();
                        
                        // Pull message header.
                        var headerO = objects[0];
                        var cryptoContexts = [];
                        Header.parseHeader(ctx, headerO, cryptoContexts, {
                            result: function(x) { header = x; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                        });
                    });
                    waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);
                    
                    var verified = false;
                    runs(function() {
                        expect(header instanceof MessageHeader).toBeTruthy();
                        var messageHeader = header;
                        
                        // Verify payloads.
                        var payloadCryptoContext = messageHeader.cryptoContext;
                        function f(i) {
                            if (i >= PAYLOADS.length) {
                                verified = true;
                                return;
                            }
                            var expectedPayload = PAYLOADS[i];
                            var payloadMo = objects[i + 1];
                            PayloadChunk.parse(ctx, payloadMo, payloadCryptoContext, {
                                result: function(payload) {
                                    var data = payload.data;
                                    expect(data).toEqual(expectedPayload);
                                    f(i+1);
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                            });
                        }
                        f(0);
                    });
                    waitsFor(function() { return verified; }, "verified", MslTestConstants.TIMEOUT);
                    
                    var closed = false;
                    runs(function() {
                        // Close tokenizer.
                        tokenizer.close(-1, {
                            result: function(x) { closed = x; },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                        });
                    });
                    waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
                });
            });
        });
    });
    
    /** Container unit tests. */
    describe("Container", function() {
        /**
         * Return the 32-bit integer value of a number.
         * 
         * @param {number} n the number.
         * @returns the integer value of the number.
         */
        function intValue(n) {
            // The << 0 operation converts to a signed 32-bit integer.
            return n << 0;
        }
        
        /**
         * Return the long value of a number.
         * 
         * @param {number} n the number.
         * @returns the long value of the number.
         */
        function longValue(n) {
            // The parseInt function converts to the integer value.
            return parseInt(n);
        }
        
        /**
         * Return the floating point value of a number.
         * 
         * @param {number} n the number.
         * @returns the floating point value of the number.
         */
        function doubleValue(n) {
            return n;
        }
        
        /**
         * Compare two numbers. The expected value is the original value. The
         * candidate value is the value that was the original was converted
         * into when retrieving it from the container.
         * 
         * @param {string} type the expected type.
         * @param {number} expected the expected value.
         * @param {number} candidate the value to test.
         * @return {boolean} true if the two numbers are equal.
         */
        function numbersEqual(type, expected, candidate) {
            // Take the expected value and convert it to the candidate value's
            // type.
            if ("integer" == type)
                return intValue(expected) == intValue(candidate);
            if ("long" == type)
                return longValue(expected) == longValue(candidate);
            if ("double" == type)
                return doubleValue(expected) == doubleValue(candidate);
            return false;
        }

        it("create object", function() {
            var key, type, value, expected, typedValue;
            
            // Create the object.
            var mo = encoder.createObject();
            expect(mo).not.toBeNull();

            // Populate it with some stuff.
            var map = {};
            var types = {};
            for (var j = 0; j < MAX_NUM_ELEMENTS; ++j) {
                key = MSL_OBJECT_KEY + ":" + j;
                var typeValue = createRandomValue();
                type = typeValue.type;
                value = typeValue.value;
                types[key] = type;
                map[key] = value;
                mo.put(key, value);
            }

            // Verify object state.
            for (key in map) {
                expected = map[key];
                value = mo.get(key);
                expect(value).toEqual(expected);
                type = types[key];
                typedValue = getTypedField(key, type, mo);
                expect(typedValue).toEqual(expected);
            }
            
            // Verify opt functions.
            for (key in map) {
                expected = map[key];
                value = mo.opt(key);
                expect(value).toEqual(expected);
                type = types[key];
                typedValue = optTypedField(key, type, mo);
                expect(typedValue).toEqual(expected);
            }
            
            // Verify opt functions with mismatched type.
            for (key in map) {
                expected = map[key];
                type = types[key];
                var randomType = getRandomType();
                typedValue = optTypedField(key, randomType, mo);
                
                // opt function returns the value if the type is correct...
                if (type == randomType) {
                    expect(typedValue).toEqual(expected);
                }
                // Boolean expects false...
                else if ("boolean" == randomType) {
                    expect(typeof typedValue).toEqual("boolean");
                    expect(typedValue).toBeFalsy();
                }
                // Numbers may be cross-retrieved...
                else if (typeof expected === "number" &&
                    ("integer" == randomType ||
                     "long" == randomType ||
                     "double" == randomType))
                {
                    expect(numbersEqual(randomType, expected, typedValue)).toBeTruthy();
                }
                // Double expects NaN...
                else if ("double" == randomType) {
                    expect(typeof typedValue).toEqual("number");
                    expect(isNaN(typedValue)).toBeTruthy();
                }
                // Numbers expect zero...
                else if ("integer" == randomType || "long" == randomType) {
                    expect(typeof typedValue).toEqual("number");
                    expect(longValue(typedValue)).toEqual(0);
                }
                // byte[] expects an empty byte array...
                else if ("Uint8Array" == randomType) {
                    expect(typedValue instanceof Uint8Array).toBeTruthy();
                    expect(typedValue).toEqual(new Uint8Array(0));
                }
                // String expects the empty string...
                else if ("string" == randomType) {
                    expect(typeof typedValue).toEqual("string");
                    expect(typedValue).toEqual("");
                }
                // Everything else expects null.
                else {
                    expect(typedValue).toBeNull();
                }
            }
            
            // Verify opt functions with default value.
            expect(mo.optBoolean("boolean", true)).toBeTruthy();
            var b = new Uint8Array(10);
            random.nextBytes(b);
            expect(mo.optBytes("bytes", b)).toEqual(b);
            var d = random.nextDouble();
            expect(mo.optDouble("double", d)).toEqual(d);
            var i = random.nextInt();
            expect(mo.optInt("integer", i)).toEqual(i);
            expect(mo.optMslArray("array")).toBeNull();
            expect(mo.optMslObject("object", encoder)).toBeNull();
            var l = random.nextLong();
            expect(mo.optLong("long", l)).toEqual(l);
            var s = Base64.encode(b);
            expect(mo.optString("string", s)).toEqual(s);
        });

        it("create object from map", function() {
            var key, type, value;
            
            // Generate some values.
            var map = {};
            var types = {};
            for (var i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                key = MSL_OBJECT_KEY + ":" + i;
                var typeValue = createRandomValue();
                type = typeValue.type;
                value = typeValue.value;
                map[key] = value;
                types[key] = type;
            }

            // Create the object.
            var mo = encoder.createObject(map);
            expect(mo).not.toBeNull();

            // Verify object state.
            for (key in map) {
                var expected = map[key];
                type = types[key];
                value = mo.get(key);
                expect(value).toEqual(expected);
                var typedValue = getTypedField(key, type, mo);
                expect(typedValue).toEqual(expected);
            }
        });

        it("create array", function() {
            var type, value, expected, typedValue;
            
            // Create the array.
            var ma = encoder.createArray();
            expect(ma).not.toBeNull();

            // Populate it with some stuff.
            var list = [];
            var types = [];
            for (var m = 0; m < MAX_NUM_ELEMENTS; ++m) {
                var typeValue = createRandomValue();
                type = typeValue.type;
                value = typeValue.value;
                list.push(value);
                types.push(type);
                ma.put(-1, value);
            }

            // Verify array state.
            for (var n = 0; n < list.length; ++n) {
                expected = list[n];
                value = ma.get(n);
                expect(value).toEqual(expected);
                type = types[n];
                typedValue = getTypedElement(n, type, ma);
                expect(typedValue).toEqual(expected);
            }
            
            // Verify opt functions.
            for (var o = 0; o < list.length; ++o) {
                expected = list[o];
                value = ma.opt(o);
                expect(value).toEqual(expected);
                type = types[o];
                typedValue = optTypedElement(o, type, ma);
                expect(typedValue).toEqual(expected);
            }
            
            // Verify opt functions with mismatched type.
            for (var p = 0; p < list.length; ++p) {
                expected = list[p];
                type = types[p];
                var randomType = getRandomType();
                typedValue = optTypedElement(p, randomType, ma);
                
                // opt function returns the value if the type is correct...
                if (type == randomType) {
                    expect(typedValue).toEqual(expected);
                }
                // Boolean expects false...
                else if ("boolean" == randomType) {
                    expect(typeof typedValue).toEqual("boolean");
                    expect(typedValue).toBeFalsy();
                }
                // Numbers may be cross-retrieved...
                else if (typeof expected === "number" &&
                    ("integer" == randomType ||
                     "long" == randomType ||
                     "double" == randomType))
                {
                    expect(numbersEqual(randomType, expected, typedValue)).toBeTruthy();
                }
                // Double expects NaN...
                else if ("double" == randomType) {
                    expect(typeof typedValue).toEqual("number");
                    expect(isNaN(typedValue)).toBeTruthy();
                }
                // Numbers expect zero...
                else if ("integer" == randomType || "long" == randomType) {
                    expect(typeof typedValue).toEqual("number");
                    expect(longValue(typedValue)).toEqual(0);
                }
                // byte[] expects an empty byte array...
                else if ("Uint8Array" == randomType) {
                    expect(typedValue instanceof Uint8Array).toBeTruthy();
                    expect(typedValue).toEqual(new Uint8Array(0));
                }
                // String expects the empty string...
                else if ("string" == randomType) {
                    expect(typeof typedValue).toEqual("string");
                    expect(typedValue).toEqual("");
                }
                // Everything else expects null.
                else {
                    expect(typedValue).toBeNull();
                }
            }
            
            // Verify opt functions with default value.
            ma.put(0, null);
            expect(ma.optBoolean(0, true)).toBeTruthy();
            var b = new Uint8Array(10);
            random.nextBytes(b);
            expect(ma.optBytes(0, b)).toEqual(b);
            var d = random.nextDouble();
            expect(ma.optDouble(0, d)).toEqual(d);
            var i = random.nextInt();
            expect(ma.optInt(0, i)).toEqual(i);
            expect(ma.optMslArray(0)).toBeNull();
            expect(ma.optMslObject(0, encoder)).toBeNull();
            var l = random.nextLong();
            expect(ma.optLong(0, l)).toEqual(l);
            var s = Base64.encode(b);
            expect(ma.optString(0, s)).toEqual(s);
        });

        it("create array from collection", function() {
            var type, value;
            
            // Generate some elements.
            var list = [];
            var types = [];
            for (var i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                var typeValue = createRandomValue();
                type = typeValue.type;
                value = typeValue.value;
                list.push(value);
                types.push(type);
            }

            // Create the array.
            var ma = encoder.createArray(list);
            expect(ma).not.toBeNull();

            // Verify array state.
            for (var j = 0; j < list.length; ++j) {
                var expected = list[j];
                value = ma.get(j);
                expect(value).toEqual(expected);
                type = types[j];
                var typedValue = getTypedElement(j, type, ma);
                expect(typedValue).toEqual(expected);
            }
        });
    });
    
    /** Accessor unit tests. */
    parameterize("Accessor", function() {
        return [
           [ null ],
           [ "boolean" ],
           [ "Uint8Array" ],
           [ "double" ],
           [ "integer" ],
           [ "MslArray" ],
           [ "MslObject" ],
           [ "long" ],
           [ "string" ],
        ];
    },
    /**
     * @param {?string} accessor type.
     */
    function(type) {
        it("object get with null key", function() {
            var f = function() {
                var mo = encoder.createObject();
                getTypedField(null, type, mo);
            };
            expect(f).toThrow(new TypeError());
        });
        
        it("object get null value", function() {
            var f = function() {
                var mo = encoder.createObject();
                getTypedField(MSL_OBJECT_KEY, type, mo);
            };
            expect(f).toThrow(new MslEncoderException());
        });
        
        it("object opt with null key", function() {
            var f = function() {
                var mo = encoder.createObject();
                optTypedField(null, type, mo);
            };
            expect(f).toThrow(new TypeError());
        });
        
        it("object opt default with null key", function() {
            var f = function() {
                var mo = encoder.createObject();
                optDefaultTypedField(null, type, mo);
            };
            expect(f).toThrow(new TypeError());
        });
        
        it("object put with key null", function() {
            var f = function() {
                var mo = encoder.createObject();
                var value = createTypedValue(type);
                putTypedField(null, type, value, mo);
            };
            expect(f).toThrow(new TypeError());
        });
        
        it("object put null value", function() {
            // Null value is incompatible with this test.
            if (type != null) {
                var mo = encoder.createObject();
                var value = createTypedValue(type);
                putTypedField(MSL_OBJECT_KEY, type, value, mo);
                expect(mo.has(MSL_OBJECT_KEY)).toBeTruthy();
                putTypedField(MSL_OBJECT_KEY, type, null, mo);
                expect(mo.has(MSL_OBJECT_KEY)).toBeFalsy();
            }
        });
        
        it("array get with negative index", function() {
            var f = function() {
                var ma = encoder.createArray();
                getTypedElement(-1, type, ma);
            };
            expect(f).toThrow(new RangeError());
        });
        
        it("array get null element", function() {
            var f = function() {
                var ma = encoder.createArray();
                putTypedElement(0, type, null, ma);
                expect(ma.size()).toEqual(1);
                getTypedElement(0, type, ma);
            };
            expect(f).toThrow(new MslEncoderException());
        });
        
        it("array opt with negative index", function() {
            var f = function() {
                var ma = encoder.createArray();
                optTypedElement(-1, type, ma);
            };
            expect(f).toThrow(new RangeError());
        });
        
        it("array opt default with negative index", function() {
            var f = function() {
                var ma = encoder.createArray();
                optDefaultTypedElement(-1, type, ma);
            };
            expect(f).toThrow(new RangeError());
        });

        it("array get with too big index", function() {
            var f = function() {
                var ma = encoder.createArray();
                getTypedElement(ma.size(), type, ma);
            };
            expect(f).toThrow(new RangeError());
        });
        
        it("array opt with too big index", function() {
            var f = function() {
                var ma = encoder.createArray();
                optTypedElement(ma.size(), type, ma);
            };
            expect(f).toThrow(new RangeError());
        });
        
        it("array opt default with too big index", function() {
            var f = function() {
                var ma = encoder.createArray();
                optDefaultTypedElement(ma.size(), type, ma);
            };
            expect(f).toThrow(new RangeError());
        });
        
        it("array put with negative index", function() {
            var f = function() {
                var ma = encoder.createArray();
                var value = createTypedValue(type);
                putTypedElement(-2, type, value, ma);
            };
            expect(f).toThrow(new RangeError());
        });
    });
    
    /** Encoding unit tests. */
    parameterize("Encoding", function() {
        return [
            [ MslEncoderFormat.JSON ],
        ];
    },
    function(format) {
        it("encode and parse object", function() {
            // Generate some values.
            var map = {};
            for (var i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                var key = MSL_OBJECT_KEY + ":" + i;
                var valueType = createRandomValue();
                var value = valueType.value;
                map[key] = value;
            }

            // Create the object.
            var mo = encoder.createObject(map);
            expect(mo).not.toBeNull();

            var encode;
            runs(function() {
                // Encode.
                encoder.encodeObject(mo, format, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(encode).not.toBeNull();
                
                // Parse.
                var parsedMo = encoder.parseObject(encode);
                expect(MslEncoderUtils.equalObjects(mo, parsedMo)).toBeTruthy();
            });
        });

        it("parse invalid object", function() {
            // Generate some values.
            var map = {};
            for (var i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                var key = MSL_OBJECT_KEY + ":" + i;
                var valueType = createRandomValue();
                var value = valueType.value;
                map[key] = value;
            }

            // Create the object.
            var mo = encoder.createObject(map);
            expect(mo).not.toBeNull();

            var encode;
            runs(function() {
                // Encode.
                encoder.encodeObject(mo, format, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(encode).not.toBeNull();
    
                // Corrupt the encode.
                encode[0] = 0;
                encode[encode.length - 1] = 'x';
                
                // Parse.
                var f = function() {
                    encoder.parseObject(encode);
                };
                expect(f).toThrow(new MslEncoderException());
            });
        });
    });
});
