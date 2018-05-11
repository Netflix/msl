/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License") {},
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
 * <p>A {@code MslObject} is an unordered collection of name/value pairs. It is
 * functionally equivalent to a JSON object, in that it encodes the pair data
 * without imposing any specific order and may contain more or less pairs than
 * explicitly defined.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>MslArray</code>, <code>MslObject</code>, <code>Number</code>, or
 * <code>String</code>.</p>
 * 
 * <p>The generic <code>get()</code> and <code>opt()</code> methods return
 * an object, which you can cast or query for type. There are also typed
 * <code>get</code> and <code>opt</code> methods that do type checking and type
 * coercion for you. The opt methods differ from the get methods in that they
 * do not throw. Instead, they return a specified value, such as null.</p>
 * 
 * <p>The <code>put</code> methods add or replace values in an object.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodable = require('../io/MslEncodable.js');
	
    // Cyclic dependency declarations.
	var MslEncoderFactory,
	    MslArray,
	    MslEncoderUtils;

    /**
     * @interface
     */
	var MslObject = module.exports = Class.create({
        /**
         * Create a new {@code MslObject} from the given optional object.
         * 
         * @param {?Object<string,*>} map the map of name/value pairs. This must be a map of
         *        {@code String}s onto values. May be {@code null}.
         * @throws TypeError if one of the values is of an
         *         unsupported type.
         */
        init: function init(map) {
            // Cyclic dependency assignments.
            if (!MslEncoderFactory) MslEncoderFactory = require('../io/MslEncoderFactory.js');
            if (!MslArray) MslArray = require('../io/MslArray.js');
            if (!MslEncoderUtils) MslEncoderUtils = require('../io/MslEncoderUtils.js');
            
            // The properties.
            var props = {
                /**
                 * Object map.
                 * @type {Object<string,*>}
                 */
                map: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            // Populate map.
            if (map) {
                for (var key in map) {
                    if (!(key instanceof String) && typeof key !== 'string')
                        throw new TypeError("Map key is not a string.");
                    var value = map[key];
                    this.put(key, value);
                }
            }
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {?} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of a proper
         *         type or the value is {@code null}.
         */
        get: function get(key) {
            if (key instanceof String)
                key = key.valueOf();
            if (typeof key !== 'string')
                throw new TypeError("Unsupported key.");
            var o = this.map[key];
            if (o === null || o === undefined)
                throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] not found.");
            if (o instanceof Object && o.constructor === Object)
                return new MslObject(o);
            if (o instanceof Array)
                return new MslArray(o);
            return o;
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {boolean} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getBoolean: function getBoolean(key) {
            var o = this.get(key);
            if (o instanceof Boolean)
                return o.valueOf();
            if (typeof o === 'boolean')
                return o;
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a boolean.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {Uint8Array} the value.
         * @throws TyoeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getBytes: function getBytes(key) {
            var o = this.get(key);
            if (o instanceof Uint8Array)
                return o;
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not binary data.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getDouble: function getDouble(key) {
            var o = this.get(key);
            if (o instanceof Number)
                return o.valueOf();
            if (typeof o === 'number')
                return o;
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getInt: function getInt(key) {
            var o = this.get(key);
            // The << 0 operation converts to a signed 32-bit integer.
            if (o instanceof Number)
                return o.valueOf() << 0;
            if (typeof o === 'number')
                return o << 0;
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {MslArray} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getMslArray: function getMslArray(key) {
            var o = this.get(key);
            if (o instanceof MslArray)
                return o;
            if (o instanceof Array)
                return new MslArray(o);
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslArray.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @param {MslEncoderFactory} encoder the MSL encoder factory.
         * @return {MslObject} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getMslObject: function getMslObject(key, encoder) {
            var o = this.get(key);
            if (o instanceof MslObject)
                return o;
            /* FIXME: How should we handle MslEncodable?
            if (o instanceof MslEncodable)
                return ((MslEncodable)o).toMslObject(encoder);
            */
            if (o instanceof Object && o.constructor === Object)
                return new MslObject(o);
            if (o instanceof Uint8Array) {
                try {
                    return encoder.parseObject(o);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslObject.");
                    throw e;
                }
            }
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslObject.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getLong: function getLong(key) {
            var o = this.get(key);
            // I don't know of a better way than using parseInt().
            if (o instanceof Number)
                return parseInt(o.valueOf());
            if (typeof o === 'number')
                return parseInt(o);
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
        },
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {string} the value.
         * @throws TypeError if the key is not a string.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getString: function getString(key) {
            var o = this.get(key);
            if (o instanceof String)
                return o.valueOf();
            if (typeof o === 'string')
                return o;
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a string.");
        },
    
        /**
         * Return true if the specified key exists. The value may be {@code null}.
         * 
         * @param {string} key the key.
         * @throws TypeError if the key is not a string.
         */
        has: function has(key) {
            if (typeof key !== 'string')
                throw new TypeError("Null key.");
            return this.map.hasOwnProperty(key);
        },
    
        /**
         * Return the value associated with the specified key or {@code null} if
         * the key is unknown.
         * 
         * @param {string} key the key.
         * @return {?} the value. May be {@code null}.
         * @throws TypeError if the key is not a string.
         */
        opt: function opt(key) {
            if (key instanceof String)
                key = key.valueOf();
            if (typeof key !== 'string')
                throw new TypeError("Unsupported key.");
            var o = this.map[key];
            try {
                if (o instanceof Object && o.constructor === Object)
                    return new MslObject(o);
                if (o instanceof Array)
                    return new MslArray(o);
            } catch (e) {
                if (o instanceof TypeError)
                    return null;
            }
            return o;
        },
    
        /**
         * Return the value associated with the specified key, or {@code false}
         * or the default value if the key is unknown or the value is not of
         * the correct type.
         * 
         * @param {string} key the key.
         * @param {boolean=} defaultValue the optional default value.
         * @return {boolean} the value.
         * @throws TypeError if the key is not a string.
         */
        optBoolean: function optBoolean(key, defaultValue) {
            var o = this.opt(key);
            if (o instanceof Boolean)
                return o.valueOf();
            if (typeof o === 'boolean')
                return o;
            if (defaultValue instanceof Boolean)
                return defaultValue.valueOf();
            if (typeof defaultValue === 'boolean')
                return defaultValue;
            return false;
        },

        /**
         * Return the value associated with the specified key, or an empty byte
         * array or the default value if the key is unknown or the value is not
         * of the correct type.
         * 
         * @param {string} key the key.
         * @param {Uint8Array=} defaultValue the default value.
         * @return {Uint8Array} the value.
         * @throws TypeError if the key is not a string.
         */
        optBytes: function optBytes(key, defaultValue) {
            var o = this.opt(key);
            if (o instanceof Uint8Array)
                return o;
            if (defaultValue instanceof Uint8Array || defaultValue === null)
                return defaultValue;
            return new Uint8Array(0);
        },
    
        /**
         * Return the value associated with the specified key, or {@code NaN}
         * or the default value if the key is unknown or the value is not of
         * the correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         */
        optDouble: function(key, defaultValue) {
            var o = this.opt(key);
            if (o instanceof Number)
                return o.valueOf();
            if (typeof o === 'number')
                return o;
            if (defaultValue instanceof Number)
                return defaultValue.valueOf();
            if (typeof defaultValue === 'number')
                return defaultValue;
            return NaN;
        },
    
        /**
         * Return the value associated with the specified key, or zero or
         * the default value if the key is unknown or the value is not of the
         * correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         */
        optInt: function optInt(key, defaultValue) {
            var o = this.opt(key);
            // The << 0 operation converts to a signed 32-bit integer.
            if (o instanceof Number)
                return o.valueOf() << 0;
            if (typeof o === 'number')
                return o << 0;
            if (defaultValue instanceof Number)
                return defaultValue.valueOf() << 0;
            if (typeof defaultValue === 'number')
                return defaultValue << 0;
            return 0;
        },
        
        /**
         * Return the {@code MslArray} associated with the specified key or
         * {@code null} if the key is unknown or the value is not of the correct
         * type.
         * 
         * @param {string} key the key.
         * @return {MslArray} the {@code MslArray}.
         * @throws TypeError if the key is not a string.
         */
        optMslArray: function optMslArray(key) {
            var o = this.opt(key);
            if (o instanceof MslArray)
                return o;
            if (o instanceof Array)
                return new MslArray(o);
            return null;
        },
    
        /**
         * Return the {@code MslObject} associated with the specified key or
         * {@code null} if the key unknown or the value is not of the correct type.
         * 
         * @param {string} key the key.
         * @param {MslEncoderFactory} encoder the MSL encoder factory.
         * @return {MslObject} the {@code MslObject}.
         * @throws TypeError if the key is not a string.
         */
        optMslObject: function optMslObject(key, encoder) {
            var o = this.opt(key);
            if (o instanceof MslObject)
                return o;
            /* FIXME: How should we handle MslEncodable?
            if (o instanceof MslEncodable) {
                try {
                    return ((MslEncodable)o).toMslObject(encoder);
                } catch (final MslEncoderException e) {
                    // Drop through.
                }
            }
            */
            if (o instanceof Object && o.constructor === Object)
                return new MslObject(o);
            if (o instanceof Uint8Array) {
                try {
                    return encoder.parseObject(o);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        return null;
                    throw e;
                }
            }
            return null;
        },
    
        /**
         * Return the value associated with the specified key, or zero or
         * the default value if the key is unknown or the value is not of the
         * correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is not a string.
         */
        optLong: function optLong(key, defaultValue) {
            var o = this.opt(key);
            // I don't know of a better way than using parseInt().
            if (o instanceof Number)
                return parseInt(o.valueOf());
            if (typeof o === 'number')
                return parseInt(o);
            if (defaultValue instanceof Number)
                return parseInt(defaultValue.valueOf());
            if (typeof defaultValue === 'number')
                return parseInt(defaultValue);
            return 0;
        },
    
        /**
         * Return the value associated with the specified key, or the empty
         * string or the default value if the key is unknown or the value is
         * not of the correct type.
         * 
         * @param {string} key the key.
         * @param {string=} defaultValue the default value.
         * @return {string} the value.
         * @throws TypeError if the key is not a string.
         */
        optString: function optString(key, defaultValue) {
            var o = this.opt(key);
            if (o instanceof String)
                return o.valueOf();
            if (typeof o === 'string')
                return o;
            if (defaultValue instanceof String)
                return defaultValue.valueOf();
            if (typeof defaultValue === 'string' || defaultValue === null)
                return defaultValue;
            return '';
        },
        
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {?} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the
         *         value is of an unsupported type.
         */
        put: function put(key, value) {
            if (key instanceof String)
                key = key.valueOf();
            if (typeof key !== 'string')
                throw new TypeError("Unsupported key.");
            
            // Remove if requested.
            if (value === null) {
                delete this.map[key];
                return this;
            }
            
            // Otherwise set.
            if (value instanceof Boolean ||
                typeof value === 'boolean' ||
                value instanceof Uint8Array ||
                value instanceof Number ||
                typeof value === 'number' ||
                value instanceof MslObject ||
                value instanceof MslArray ||
                value instanceof String ||
                typeof value === 'string' ||
                value instanceof MslEncodable)
            {
                this.map[key] = value;
            }
            else if (value instanceof Object && value.constructor === Object)
                this.map[key] = new MslObject(value);
            else if (value instanceof Array)
                this.map[key] = new MslArray(value);
            else
                throw new TypeError("Value [" + typeof value + "] is an unsupported type.");
            return this;
        },
        
        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {boolean} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putBoolean: function putBooleans(key, value) {
            if (!(value instanceof Boolean) && typeof value !== 'boolean' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a boolean");
            return this.put(key, value);
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {Uint8Array} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putBytes: function putBytes(key, value) {
            if (!(value instanceof Uint8Array) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not binary data.");
            return this.put(key, value);
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. The collection of
         * elements will be transformed into a {@code MslArray}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {Array<?>} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putCollection: function putCollection(key, value) {
            if (!(value instanceof Array) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a collection.");
            return this.put(key, value);
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putDouble: function putDouble(key, value) {
            if (!(value instanceof Number) && typeof value !== 'number' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a number.");
            return this.put(key, value);
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putInt: function putInt(key, value) {
            // The << 0 operation converts to a signed 32-bit integer.
            if (value instanceof Number)
                return this.put(key, value.valueOf() << 0);
            if (typeof value === 'number')
                return this.put(key, value << 0);
            if (value === null)
            	return this.put(key, value);
            throw new TypeError("Value [" + typeof value + "] is not a number.");
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putLong: function putLong(key, value) {
            // The parseInt function converts to the integer value.
            if (value instanceof Number)
                return this.put(key, parseInt(value.valueOf()));
            if (typeof value === 'number')
                return this.put(key, parseInt(value));
            if (value === null)
            	return this.put(key, value);
            throw new TypeError("Value [" + typeof value + "] is not a number.");
        },
    
        /**
         * <p>Put a key/value pair into the {@code MslObject}. The map of strings
         * onto objects will be transformed into a {@code MslObject}. If the value
         * is {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {object} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string, the value is of the
         *         incorrect type, or one of the values in the map is an
         *         unsupported type.
         */
        putMap: function putMap(key, value) {
            if (!(value instanceof Object && value.constructor === Object) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a map.");
            return this.put(key, value);
        },

        /**
         * <p>Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.</p>
         * 
         * <p>This method will call {@link #put(String, Object)}.</p>
         * 
         * @param {string} key the key.
         * @param {string} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is not a string or the value is of the
         *         incorrect type.
         */
        putString: function putString(key, value) {
            if (!(value instanceof String) && typeof value !== 'string' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a string.");
            return this.put(key, value);
        },
        
        /**
         * Remove a key and its associated value from the {@code MslObject}.
         * 
         * @param {string} key the key.
         * @return {?} the removed value. May be {@code null}.
         * @throws TypeError if the key is not a string.
         */
        remove: function remove(key) {
            if (key instanceof String)
                key = key.valueOf();
            if (typeof key !== 'string')
                throw new TypeError("Unsupported key.");
            var o = this.opt(key);
            delete this.map[key];
            return o;
        },
        
        /**
         * Return an unmodifiable set of the {@code MslObject} keys.
         * 
         * @return {Array<string>} the unmodifiable set of the {@code MslObject} keys.
         */
        getKeys: function getKeys() {
            return Object.keys(this.map);
        },
        
        /**
         * Return a map of the {@code MslObject} contents.
         * 
         * @return {object} the map of {@code MslObject} contents.
         */
        getMap: function getMap() {
            var clone = {};
            for (var key in this.map)
                clone[key] = this.map[key];
            return clone;
        },
        
        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a {@code MslObject}
         *         with the same keys and values.
         */
        equals: function equals(that) {
        	if (this == that) return true;
        	if (!(that instanceof MslObject)) return false;
        	try {
        		return MslEncoderUtils.equalObjects(this, that);
	    	} catch (e) {
	    		if (e instanceof MslEncoderException) return false;
	    		throw e;
	    	}
        },
        
        /** @inheritDoc */
        toString: function toString() {
        	return MslEncoderFactory.stringify(this.map);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslObject'));
