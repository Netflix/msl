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
 * <p>A {@code MslArray} that encodes its data as JSON.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslArray = require('../io/MslArray.js');
	var MslObject = require('../io/MslObject.js');
	var MslEncodable = require('../io/MslEncodable.js');
	var MslEncoderFormat = require('../io/MslEncoderFormat.js');
	var TextEncoding = require('../util/TextEncoding.js');
	var MslConstants = require('../MslConstants.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslException = require('../MslException.js');
	var Base64 = require('../util/Base64.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');

    // Cyclic dependency declarations.
	var JsonMslObject;
	
	var JsonMslArray = module.exports = MslArray.extend({
        /**
         * <p>Create a new {@code MslArray}.</p>
         * 
         * <p>If a source {@code MslArray}, {@code Array}, or an encoded
         * representation is provided then the array will be populated
         * accordingly.</p>
         * 
         * @param {MslEncoderFactory} encoder the encoder factory.
         * @param {{MslArray|Array.<*>|Uint8Array}=} source optional MSL array,
         *        array of elements, or encoded data.
         * @throws MslEncoderException if the data is malformed or invalid.
         * @see #getEncoded()
         */
        init: function init(encoder, source) {
            init.base.call(this);
            
            // Cyclic dependency assignments.
            if (!JsonMslObject) JsonMslObject = require('../io/JsonMslObject.js');
            
            // Set properties.
            var props = {
                encoder: { value: encoder, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            // Identify the source data.
            var ja = [];
            if (source instanceof Array) {
                ja = source;
            } else if (source instanceof MslArray) {
            	for (var i = 0; i < source.size(); ++i)
            		ja.push(source.opt(i));
            } else if (source instanceof Uint8Array) {
                try {
                    var json = TextEncoding.getString(source, TextEncoding.Encoding.UTF_8);
                    var decoded = JSON.parse(json);
                    if (!(decoded instanceof Array))
                        throw new MslEncoderException("Invalid JSON array encoding.");
                    ja = decoded;
                } catch (e) {
                    if (!(e instanceof MslException))
                        throw new MslEncoderException("Invalid JSON array encoding.", e);
                    throw e;
                }
            }
            
            // Shallow copy the source data into this MSL array.
            try {
                for (var j = 0; j < ja.length; ++j)
                    this.put(-1, ja[j]);
            } catch (e) {
                if (e instanceof TypeError)
                    throw new MslEncoderException("Invalid MSL array encoding.", e);
                throw e;
            }
        },
        
        /** @inheritDoc */
        put: function put(index, value) {
            var o;
            try {
                // Convert JSONObject to MslObject.
                if (value instanceof Object && value.constructor === Object)
                    o = new JsonMslObject(this.encoder, value);
                // Convert JSONarray to a MslArray.
                else if (value instanceof Array)
                    o = new JsonMslArray(this.encoder, value);
                // All other types are OK as-is.
                else
                    o = value;
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new TypeError("Unsupported JSON object or array representation.");
                throw e;
            }
            return put.base.call(this, index, o);
        },
        
        /** @inheritDoc */
        getBytes: function getBytes(index) {
            // When a JsonMslArray is decoded, there's no way for us to know if a
            // value is supposed to be a String to byte[]. Therefore interpret
            // Strings as Base64-encoded data consistent with the toJSONString()
            // and getEncoded().
            var value = this.get(index);
            if (value instanceof Uint8Array)
                return value;
            try {
	            if (value instanceof String)
	                return Base64.decode(value.valueOf());
	            if (typeof value === 'string')
	                return Base64.decode(value);
            } catch (e) {
                throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
            }
            throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
        },
        
        /** @inheritDoc */
        optBytes: function optBytes(key, defaultValue) {
            // When a JsonMslArray is decoded, there's no way for us to know if a
            // value is supposed to be a String to byte[]. Therefore interpret
            // Strings as Base64-encoded data consistent with the toJSONString()
            // and getEncoded().
        	var value = this.opt(key);
        	if (value instanceof Uint8Array)
        		return value;
            try {
	            if (value instanceof String)
	                return Base64.decode(value.valueOf());
	            if (typeof value === 'string')
	                return Base64.decode(value);
            } catch (e) {
                // Fall through.
            }
            if (defaultValue instanceof Uint8Array || defaultValue === null)
            	return defaultValue;
            return new Uint8Array(0);
        },
        
        /**
         * Generates and returns the JSON array.
         * 
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {{result: function(Array), error: function(Error)}} callback
         *        the callback that will receive the JSON array or any thrown
         *        exceptions.
         * @throws MslEncoderException if there is an error encoding a value.
         */
        toJSONArray: function toJSONArray(encoder, callback) {
        	var self = this;
        	
        	AsyncExecutor(callback, function() {
        		var ja = [];
        		var size = this.size();
        		next(ja, size, 0);
        	}, self);
        	
        	function next(ja, size, i) {
    			AsyncExecutor(callback, function() {
    			    var JsonMslObject = require('../io/JsonMslObject.js');
    			    
	    			if (i >= size)
	    				return ja;

	    			var value = this.opt(i);
	    			if (value instanceof Uint8Array) {
	    			    ja.push(Base64.encode(value));
	    			    next(ja, size, i+1);
	    			} else if (value instanceof JsonMslObject) {
	    			    value.toJSONObject(encoder, {
	    			        result: function(o) {
	    			            AsyncExecutor(callback, function() {
	    			                ja.push(o);
	    			                next(ja, size, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof JsonMslArray) {
	    			    value.toJSONArray(encoder, {
	    			        result: function(a) {
	    			            AsyncExecutor(callback, function() {
	    			                ja.push(a);
	    			                next(ja, size, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslObject) {
	    			    var moJsonValue = new JsonMslObject(encoder, value);
	    			    moJsonValue.toJSONObject(encoder, {
	    			        result: function(o) {
	    			            AsyncExecutor(callback, function() {
	    			                ja.push(o);
	    			                next(ja, size, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslArray) {
	    			    var maJsonValue = new JsonMslArray(encoder, value);
	    			    maJsonValue.toJSONArray(encoder, {
	    			        result: function(a) {
	    			            AsyncExecutor(callback, function() {
	    			                ja.push(a);
	    			                next(ja, size, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslEncodable) {
	    			    value.toMslEncoding(encoder, MslEncoderFormat.JSON, {
	    			        result: function(json) {
	    			            AsyncExecutor(callback, function() {
	    			                var jsonValue = new JsonMslObject(encoder, json);
	    			                jsonValue.toJSONObject(encoder, {
	    			                    result: function(o) {
	    			                        AsyncExecutor(callback, function() {
	    			                            ja.push(o);
	    			                            next(ja, size, i+1);
	    			                        }, self);
	    			                    },
	    			                    error: callback.error,
	    			                });
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else {
	    			    ja.push(value);
	    			    next(ja, size, i+1);
	        		}
    			}, self);
        	}
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonMslArray'));