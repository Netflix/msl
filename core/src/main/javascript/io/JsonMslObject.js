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
 * <p>A {@code MslObject} that encodes its data as JSON.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslArray = require('../io/MslArray.js');
	var MslObject = require('../io/MslObject.js');
	var TextEncoding = require('../util/TextEncoding.js');
	var MslConstants = require('../MslConstants.js');
	var MslEncodable = require('../io/MslEncodable.js');
	var MslEncoderFormat = require('../io/MslEncoderFormat.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslException = require('../MslException.js');
	var Base64 = require('../util/Base64.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
    
    // Cyclic dependency declarations.
    var MslEncoderFactory,
        JsonMslArray;
    
    /**
     * Encode the provided MSL object into JSON.
     * 
     * @param {MslEncoderFactory} encoder the encoder factory.
     * @param {MslObject} object the MSL object.
     * @param {{result: function(Uint8Array), error: function(Error)}} callback
     *        the callback that will receive the encoded data or any thrown
     *        exceptions.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    var JsonMslObject$encode = function JsonMslObject$encode(encoder, object, callback) {
        AsyncExecutor(callback, function() {
            var jsonObject = (object instanceof JsonMslObject)
                ? object
                : new JsonMslObject(encoder, object);

            jsonObject.toJSONString(encoder, {
                result: function(json) {
                    AsyncExecutor(callback, function() {
                        return TextEncoding.getBytes(json, TextEncoding.Encoding.UTF_8);
                    });
                },
                error: callback.error,
            });
        });
    };
    
    var JsonMslObject = module.exports = MslObject.extend({
        /**
         * <p>Create a new {@code JsonMslObject} from the given
         * {@code MslObject}, object map, or its encoded representation.</p>
         * 
         * <p>If a source object map or an encoded representation is provided
         * then the object will be populated accordingly.</p>
         * 
         * @param {MslEncoderFactory} encoder the encoder factory.
         * @param {{MslObject|Object<String,*>|Uint8Array}=} source the
         *        {@MslObject}, object map, or encoded data.
         * @throws MslEncoderException if the data is malformed or invalid.
         */
        init: function init(encoder, source) {
            init.base.call(this);

            // Cyclic dependency assignments.
            if (!MslEncoderFactory) MslEncoderFactory = require('../io/MslEncoderFactory.js');
            if (!JsonMslArray) JsonMslArray = require('../io/JsonMslArray.js');
            
            // Set properties.
            var props = {
                encoder: { value: encoder, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            try {
                var key;
                
                // MslObject
                if (source instanceof MslObject) {
                    var keys = source.getKeys();
                    for (var i = 0; i < keys.length; ++i) {
                        key = keys[i];
                        this.put(key, source.opt(key));
                    }
                }

                // Object
                else if (source instanceof Object && source.constructor === Object) {
                    for (key in source) {
                        if (!(key instanceof String) && typeof key !== 'string')
                            throw new MslEncoderException("Invalid JSON object encoding.");
                        this.put(key, source[key]);
                    }
                }

                // Uint8Array
                else if (source instanceof Uint8Array) {
                    var json = TextEncoding.getString(source, TextEncoding.Encoding.UTF_8);
                    var jo = JSON.parse(json);
                    if (!(jo instanceof Object) || jo.constructor !== Object)
                        throw new MslEncoderException("Invalid JSON object encoding.");
                    for (key in jo) {
                        if (!(key instanceof String) && typeof key !== 'string')
                            throw new MslEncoderException("Invalid JSON object encoding.");
                        this.put(key, jo[key]);
                    }
                }
            } catch (e) {
                if (e instanceof TypeError)
                    throw new MslEncoderException("Invalid MSL object encoding.", e);
            	if (!(e instanceof MslException))
                    throw new MslEncoderException("Invalid JSON object encoding.", e);
                throw e;
            }
        },
        
        /** @inheritDoc */
        put: function put(key, value) {
            var o;
            try {
                // Convert Object to MslObject.
                if (value instanceof Object && value.constructor === Object)
                    o = new JsonMslObject(this.encoder, value);
                // Convert Array to MslArray.
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
            return put.base.call(this, key, o);
        },

        /** @inheritDoc */
        getBytes: function getBytes(key) {
            // When a JsonMslObject is decoded, there's no way for us to know if a
            // value is supposed to be a String to byte[]. Therefore interpret
            // Strings as Base64-encoded data consistent with the toJSONString()
            // and getEncoded().
            var value = this.get(key);
            if (value instanceof Uint8Array)
                return value;
            try {
	            if (value instanceof String)
	                return Base64.decode(value.valueOf());
	            if (typeof value === 'string')
	                return Base64.decode(value);
            } catch (e) {
                throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not binary data.");
            }
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not binary data.");
        },
        
        /** @inheritDoc */
        optBytes: function optBytes(key, defaultValue) {
            // When a JsonMslObject is decoded, there's no way for us to know if a
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
         * Generates and returns the JSON object.
         * 
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {{result: function(Object), error: function(Error)}} callback
         *        the callback that will receive the JSON object or any thrown
         *        exceptions.
         * @throws MslEncoderException if there is an error encoding a value.
         */
        toJSONObject: function toJSONObject(encoder, callback) {
        	var self = this;
        	
        	AsyncExecutor(callback, function() {
        		var jo = {};
        		var keys = this.getKeys();
        		next(jo, keys, 0);
        	}, self);

    		function next(jo, keys, i) {
    			AsyncExecutor(callback, function() {
    			    var JsonMslArray = require('../io/JsonMslArray.js');
    			    
	    			if (i >= keys.length)
	    				return jo;

	    			var key = keys[i];
	    			var value = this.opt(key);
	    			if (value instanceof Uint8Array) {
	    			    jo[key] = Base64.encode(value);
	    			    next(jo, keys, i+1);
	    			} else if (value instanceof JsonMslObject) {
	    			    value.toJSONObject(encoder, {
	    			        result: function(o) {
	    			            AsyncExecutor(callback, function() {
	    			                jo[key] = o;
	    			                next(jo, keys, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof JsonMslArray) {
	    			    value.toJSONArray(encoder, {
	    			        result: function(a) {
	    			            AsyncExecutor(callback, function() {
	    			                jo[key] = a;
	    			                next(jo, keys, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslObject) {
	    			    var moJsonValue = new JsonMslObject(encoder, value);
	    			    moJsonValue.toJSONObject(encoder, {
	    			        result: function(o) {
	    			            AsyncExecutor(callback, function() {
	    			                jo[key] = o;
	    			                next(jo, keys, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslArray) {
	    			    var maJsonValue = new JsonMslArray(encoder, value);
	    			    maJsonValue.toJSONArray(encoder, {
	    			        result: function(a) {
	    			            AsyncExecutor(callback, function() {
	    			                jo[key] = a;
	    			                next(jo, keys, i+1);
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else if (value instanceof MslEncodable) {
	    			    value.toMslEncoding(encoder, MslEncoderFormat.JSON, {
	    			        result: function(json) {
	    			            AsyncExecutor(callback, function() {
	    			                var meJsonValue = new JsonMslObject(encoder, json);
	    			                meJsonValue.toJSONObject(encoder, {
	    			                    result: function(o) {
	    			                        AsyncExecutor(callback, function() {
	    			                            jo[key] = o;
	    			                            next(jo, keys, i+1);
	    			                        }, self);
	    			                    },
	    			                    error: callback.error,
	    			                });
	    			            }, self);
	    			        },
	    			        error: callback.error,
	    			    });
	    			} else {
	    			    jo[key] = value;
	    			    next(jo, keys, i+1);
	    			}
    			}, self);
    		}
        },
        
        /**
         * Returns the JSON serialization.
         * 
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {{result: function(string), error: function(Error)}} callback
         *        the callback that will receive the JSON string or any thrown
         *        exceptions.
         * @throws MslEncoderException if there is an error encoding a value.
         */
        toJSONString: function toJSONString(encoder, callback) {
        	var self = this;
        	this.toJSONObject(encoder, {
        		result: function(jo) {
        			AsyncExecutor(callback, function() {
        				return JSON.stringify(jo);
        			}, self);
        		},
        		error: callback.error,
        	});
        }
    });
    
    // Exports.
    module.exports.encode = JsonMslObject$encode;
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonMslObject'));