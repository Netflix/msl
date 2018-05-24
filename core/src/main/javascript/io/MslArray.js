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
 * <p>A {@code MslArray} is an ordered sequence of values.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>Byte[]</code> <code>MslArray</code>, <code>MslObject</code>,
 * <code>Number</code>, or <code>String</code>.</p>
 * 
 * <p>The generic <code>get()</code> and <code>opt()</code> methods return an
 * object, which you can cast or query for type. There are also typed
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
        MslObject,
        MslEncoderUtils;

    /**
     * @interface
     */
    var MslArray = module.exports = Class.create({
        /**
         * Create a new {@code MslArray} from the given optional object array.
         * 
         * @param {?Array<*>=} array the array of values. May be {@code null}.
         * @throws TypeError if one of the values is of an
         *         unsupported type.
         */
        init: function init(array) {
            // Cyclic dependency assignments.
            if (!MslEncoderFactory) MslEncoderFactory = require('../io/MslEncoderFactory.js');
            if (!MslObject) MslObject = require('../io/MslObject.js');
            if (!MslEncoderUtils) MslEncoderUtils = require('../io/MslEncoderUtils.js');
            
            // The properties.
            var props = {
                /**
                 * Object list.
                 * @type {Array.<*>}
                 */
                list: { value: [], writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            // Populate array.
            if (array) {
                for (var i = 0; i < array.length; ++i)
                    this.put(-1, array[i]);
            }
        },
        
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {?} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        get: function get(index) {
            if (index < 0 || index >= this.list.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.list[index];
            if (o === null || o === undefined)
                throw new MslEncoderException("MslArray[" + index + "] is null.");
            if (o instanceof Object && o.constructor === Object)
                return new MslObject(o);
            if (o instanceof Array)
                return new MslArray(o);
            return o;
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {boolean} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getBoolean: function getBoolean(index) {
            var o = this.get(index);
            if (o instanceof Boolean)
                return o.valueOf();
            if (typeof o === 'boolean')
                return o;
            throw new MslEncoderException("MslArray[" + index + "] is not a boolean.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {Uint8Array} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getBytes: function getBytes(index) {
            var o = this.get(index);
            if (o instanceof Uint8Array)
                return o;
            throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getDouble: function getDouble(index) {
            var o = this.get(index);
            if (o instanceof Number)
                return o.valueOf();
            if (typeof o === 'number')
                return o;
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getInt: function getInt(index) {
            var o = this.get(index);
            // The << 0 operation converts to a signed 32-bit integer.
            if (o instanceof Number)
                return o.valueOf() << 0;
            if (typeof o === 'number')
                return o << 0;
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {MslArray} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getMslArray: function getMslArray(index) {
            var o = this.get(index);
            if (o instanceof MslArray)
                return o;
            if (o instanceof Array)
                return new MslArray(o);
            throw new MslEncoderException("MslArray[" + index + "] is not a MslArray.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @param {MslEncoderFactory} encoder the MSL encoder factory.
         * @return {MslObject} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getMslObject: function getMslObject(index, encoder) {
            var o = this.get(index);
            if (o instanceof MslObject)
                return o;
            /* FIXME: How should we handle MslEncodable?
            if (o instanceof MslEncodable)
                return ((MslEncodable)o.toMslObject(encoder);
            */
            if (o instanceof Object && o.constructor === Object)
                return new MslObject(o);
            if (o instanceof Uint8Array) {
                try {
                    return encoder.parseObject(o);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncoderException("MslObject[" + index + "] is not a MslObject.", e);
                    throw e;
                }
            }
            throw new MslEncoderException("MslArray[" + index + "] is not a MslObject.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getLong: function getLong(index) {
            var o = this.get(index);
            // I don't know of a better way than using parseInt().
            if (o instanceof Number)
                return parseInt(o.valueOf());
            if (typeof o === 'number')
                return parseInt(o);
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");
        },
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {string} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null} or of the wrong
         *         type.
         */
        getString: function getString(index) {
            var o = this.get(index);
            if (o instanceof String)
                return o.valueOf();
            if (typeof o === 'string')
                return o;
            throw new MslEncoderException("MslArray[" + index + "] is not a string.");
        },
    
        /**
         * Return true if the value at the index is {@code null}.
         * 
         * @param {number} index the index.
         * @return {boolean} true if the value is null.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        isNull: function isNull(index) {
            if (index < 0 || index >= this.list.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            return this.list[index] == null;
            
        },
        
        /**
         * Return the number of elements in the array, including {@code null}
         * values.
         * 
         * @return {number} the array size.
         */
        size: function size() {
            return this.list.length;
        },
        
        /**
         * Return the value at the index.
         * 
         * @param {number} index the index.
         * @return {?} the value. May be {@code null}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        opt: function opt(index) {
            if (index < 0 || index >= this.list.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.list[index];
            try {
                if (o instanceof Object && o.constructor === Object)
                    return new MslObject(o);
                if (o instanceof Array)
                    return new MslArray(o);
            } catch (e) {
                if (e instanceof TypeError)
                    return null;
            }
            return o;
        },
        
        /**
         * Return the value at the index, or {@code false} or the default value if
         * the value is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {boolean=} defaultValue the default value.
         * @return {boolean} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optBoolean: function optBoolean(index, defaultValue) {
            var o = this.opt(index);
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
         * Return the value at the index, or an empty byte array or the default
         * value if the value is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {Uint8Array=} defaultValue the default value.
         * @return {Uint8Array} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optBytes: function optBytes(index, defaultValue) {
            var o = this.opt(index);
            if (o instanceof Uint8Array)
                return o;
            if (defaultValue instanceof Uint8Array || defaultValue === null)
                return defaultValue;
            return new Uint8Array(0);
        },
        
        /**
         * Return the value at the index, or {@code NaN} or the default value if
         * the value is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {number=} defaultValue the default value.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optDouble: function optDouble(index, defaultValue) {
            var o = this.opt(index);
            if (o instanceof Number)
                return o.valueOf();
            if (typeof o === 'number')
                return o;
            if (defaultValue instanceof Number)
                return defaultValue;
            if (typeof defaultValue === 'number')
                return defaultValue;
            return NaN;
        },
        
        /**
         * Return the value at the index, or zero or the default value if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {number=} defaultValue the default value.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optInt: function optInt(index, defaultValue) {
            var o = this.opt(index);
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
         * Return the {@code MslArray} at the index or {@code null} if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @return {MslArray} the {@code MslArray}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optMslArray: function optMslArray(index) {
            var o = this.opt(index);
            if (o instanceof MslArray)
                return o;
            if (o instanceof Array)
                return new MslArray(o);
            return null;
        },
    
        /**
         * Return the {@code MslObject} at the index or {@code null} if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {MslEncoderFactory} the MSL encoder factory.
         * @return {MslObject} the {@code MslObject}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optMslObject: function optMslObject(index, encoder) {
            var o = this.opt(index);
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
            try {
                if (o instanceof Object && o.constructor === Object)
                    return new MslObject(o);
            } catch (e) {
                if (e instanceof TypeError)
                    return null;
                throw e;
            }
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
         * Return the value at the index, or zero or the default value if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {number=} defaultValue the default value.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optLong: function optLong(index, defaultValue) {
            var o = this.opt(index);
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
         * Return the value at the index, or the empty string or the default value
         * if the value is not of the correct type.
         * 
         * @param {number} index the index.
         * @param {string=} defaultValue the default value.
         * @return {string} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optString: function optString(index, defaultValue) {
            var o = this.opt(index);
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
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {?} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of an unsupported type.
         */
        put: function put(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            
            // Convert appropriate values to MSL objects or MSL arrays.
            var element;
            if (value instanceof Boolean ||
                typeof value === 'boolean' ||
                value instanceof Uint8Array ||
                value instanceof Number ||
                typeof value === 'number' ||
                value instanceof MslObject ||
                value instanceof MslArray ||
                value instanceof String ||
                typeof value === 'string' ||
                value instanceof MslEncodable ||
                value === null)
            {
                element = value;
            }
            else if (value instanceof Object && value.constructor === Object) {
                element = new MslObject(value);
            } else if (value instanceof Array) {
                element = new MslArray(value);
            } else {
                throw new TypeError("Value [" + typeof value + "] is an unsupported type.");
            }
            
            // Fill with null elements as necessary.
            for (var i = this.list.length; i < index; ++i)
                this.list.push(null);
            
            // Append if requested.
            if (index == -1 || index == this.list.length) {
                this.list.push(element);
                return this;
            }
            
            // Otherwise replace.
            this.list[index] = element;
            return this;
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {boolean} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putBoolean: function putBoolean(index, value) {
            if (!(value instanceof Boolean) && typeof value !== 'boolean' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a boolean.");
            return this.put(index, value);
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Uint8Array} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putBytes: function putBytes(index, value) {
            if (!(value instanceof Uint8Array) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not binary data.");
            return this.put(index, value);
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. The
         * collection of elements will be transformed into a {@code MslArray}.
         * If the index exceeds the length, null elements will be added as
         * necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Array<?>} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putCollection: function putCollection(index, value) {
            if (!(value instanceof Array) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a collection.");
            return this.put(index, value);
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putDouble: function putDouble(index, value) {
            if (!(value instanceof Number) && typeof value !== 'number' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a number.");
            return this.put(index, value);
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putInt: function putInt(index, value) {
            // The << 0 operation converts to a signed 32-bit integer.
            if (value instanceof Number)
                return this.put(index, value.valueOf() << 0);
            if (typeof value === 'number')
                return this.put(index, value << 0);
            if (value === null)
            	return this.put(index, value);
            throw new TypeError("Value [" + typeof value + "] is not a number.");
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putLong: function putLong(index, value) {
            // The parseInt function converts to the integer value.
            if (value instanceof Number)
                return this.put(index, parseInt(value.valueOf()));
            if (typeof value === 'number')
                return this.put(index, parseInt(value));
            if (value === null)
            	return this.put(index, value);
            throw new TypeError("Value [" + typeof value + "] is not a number.");
        },
        
        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. The
         * map of strings onto objects will be transformed into a
         * {@code MslObject}. If the index exceeds the length, null elements
         * will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Object.<String,?>} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putMap: function putMap(index, value) {
            if (!(value instanceof Object && value.constructor === Object) && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a map.");
            return this.put(index, value);
        },

        /**
         * <p>Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.</p>
         * 
         * <p>This method will call {@link #put(int, Object)}.</p>
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {string} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         * @throws TypeError if the value is of the incorrect type.
         */
        putString: function putString(index, value) {
            if (!(value instanceof String) && typeof value !== 'string' && value !== null)
                throw new TypeError("Value [" + typeof value + "] is not a string.");
            return this.put(index, value);
        },
        
        /**
         * Remove an element at the index. This decreases the length by one.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @return {?} the removed value. May be {@code null}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        remove: function remove(index) {
            if (index < -1 || index >= this.list.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var i = (index == -1) ? this.list.length - 1 : index;
            var o = this.opt(i);
            this.list.splice(index, 1);
            return o;
        },
    
        /**
         * Return a collection of the {@code MslArray} contents.
         * 
         * @return {Array.<?>} the collection of {@code MslArray} contents.
         */
        getCollection: function getCollection() {
            return this.list.slice();
        },
        
        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a {@code MslArray}
         *         with the same elements in the same order.
         */
        equals: function equals(that) {
        	if (this == that) return true;
        	if (!(that instanceof MslArray)) return false;
        	try {
        		return MslEncoderUtils.equalArrays(this, that);
        	} catch (e) {
        		if (e instanceof MslEncoderException) return false;
        		throw e;
        	}
        },
        
        /** @inheritDoc */
        toString: function toString() {
        	return MslEncoderFactory.stringify(this.list);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslArray'));
