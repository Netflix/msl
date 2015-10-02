/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
var JsonMslArray;

(function() {
    "use strict";
    
    JsonMslArray = MslArray.extend({
        /**
         * <p>Create a new {@code MslArray}.</p>
         * 
         * <p>If a source collection of elements or an encoded representation
         * is provided then the array will be populated accordingly.</p>
         * 
         * @param {{Array.<*>|Uint8Array}=} source optional collection of
         *        elements or encoded data.
         * @throws MslEncoderException if the data is malformed or invalid.
         * @see #getEncoded()
         */
        init: function init(source) {
            var ja = [];
            if (source instanceof Array) {
                ja = source.slice();
            } else if (source instanceof Uint8Array) {
                try {
                    var json = textEncoding$getString(source, MslConstants$DEFAULT_CHARSET);
                    var decoded = JSON.parse(json);
                    if (!(decoded instanceof Array))
                        throw new MslEncoderException("Invalid JSON array encoding.");
                    ja = decoded;
                } catch (e) {
                    throw new MslEncoderException("Invalid JSON array encoding.", e);
                }
            }
            
            // The properties.
            var props = {
                ja: { value: ja, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        get: function get(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            if (this.ja[index] === undefined)
                throw new MslEncoderException("MslArray[" + index + "] not found.");
            var o = this.ja[index];
            if (o instanceof Object)
                return new JsonMslObject(o);
            if (o instanceof Array)
                return new JsonMslArray(o);
            return o;
        },
        
        /** @inheritDoc */
        getBoolean: function getBoolean(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var b = this.ja[index];
            if (typeof b === 'boolean') return b;
            throw new MslEncoderException("MslArray[" + index + "] is not a boolean.");
        },
        
        /** @inheritDoc */
        getBytes: function getBytes(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var b64 = this.ja[index];
            if (typeof b64 === 'string') {
                try {
                    return base64$decode(b64);
                } catch (e) {
                    throw new MslEncoderException("MslArray[" + index + "] is not binary data.", e);
                }
            }
            throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
        },

        /** @inheritDoc */
        getDouble: function getDouble(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number')
                return x;
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");
        },

        /** @inheritDoc */
        getInt: function getInt(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number')
                return Math.floor(x) & 0xFFFFFFFF;
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");
        },

        /** @inheritDoc */
        getMslArray: function getMslArray(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var a = this.ja[index];
            if (a instanceof Array)
                return new JsonMslArray(a);
            throw new MslEncoderException("MslArray[" + index + "] is not a MslArray.");
        },

        /** @inheritDoc */
        getMslObject: function getMslObject(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.ja[index];
            if (o instanceof Object)
                return new JsonMslObject(o);
            throw new MslEncoderException("MslArray[" + index + "] is not a MslObject.");
        },

        /** @inheritDoc */
        getLong: function getLong(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number')
                return Math.floor(x);
            throw new MslEncoderException("MslArray[" + index + "] is not a number.");\
        },

        /** @inheritDoc */
        getString: function getString(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var s = this.ja[index];
            if (typeof s === 'string')
                return s;
            throw new MslEncoderException("MslArray[" + index + "] is not a string.");
        },

        /** @inheritDoc */
        isNull: function isNull(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            return this.ja[index] === null;
        },

        /** @inheritDoc */
        length: function length() {
            return this.ja.length;
        },

        /** @inheritDoc */
        opt: function opt(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.ja[index];
            if (o instanceof Object)
                return new JsonMslObject(o);
            if (o instanceof Array)
                return new JsonMslArray(o);
            return o;
        },

        /** @inheritDoc */
        optBoolean: function optBoolean(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var b = this.ja[index];
            if (typeof b === 'boolean') return b;
            if (typeof defaultValue === 'boolean') return defaultValue;
            return false;
        },
        
        /** @inheritDoc */
        optBytes: function optBytes(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var b64 = this.ja[index];
            if (typeof b64 === 'string') {
                try {
                    return base64$decode(b64);
                } catch (e) {
                    // Fall through.
                }
            }
            if (defaultValue instanceof Uint8Array) return defaultValue;
            return new Uint8Array(0);
        },

        /** @inheritDoc */
        optDouble: function optDouble(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number') return x;
            return (typeof defaultValue === 'number') ? defaultValue : Number.NaN;
        },

        /** @inheritDoc */
        optInt: function optInt(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number') return Math.floor(x) & 0xFFFFFFFF;
            return (typeof defaultValue === 'number') ? defaultValue : 0;
        },

        /** @inheritDoc */
        optMslArray: function optMslArray(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var a = this.ja[index];
            return (a instanceof Array) ? new JsonMslArray(a) : null;
        },

        /** @inheritDoc */
        optMslObject: function optMslObject(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.ja[index];
            return (o instanceof Object) ? new JsonMslObject(o) : null;
        },

        /** @inheritDoc */
        optLong: function optLong(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var x = this.ja[index];
            if (typeof x === 'number') return Math.floor(x);
            return (typeof defaultValue === 'number') ? defaultValue : 0;
        },

        /** @inheritDoc */
        optString: function optString(index, defaultValue) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var s = this.ja[index];
            if (typeof s === 'string') return s;
            return (typeof defaultValue === 'string') ? defaultValue : "";
        },

        /** @inheritDoc */
        put: funtion put(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            this.ja[(index == -1) ? this.ja.length : index] = value;
            return this;
        },

        /** @inheritDoc */
        putBoolean: function putBoolean(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            if (typeof value !== 'boolean') value = false;
            this.ja[(index == -1) ? this.ja.length : index] = value;
            return this;
        },
        
        /** @inheritDoc */
        putBytes: function putBytes(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            var b64 = (value instanceof Uint8Array) ? base64$encode(value) : null;
            this.ja[(index == -1) ? this.ja.length : index] = b64;
            return this;
        },

        /** @inheritDoc */
        putCollection: function putCollection(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            var a = (value instanceof Array) ? new JsonMslArray(value) : null;
            this.ja[(index == -1) ? this.ja.length : index] = a;
            return this;
        }

        /** @inheritDoc */
        putDouble: function putDouble(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            if (typeof value !== 'number') value = Number.NaN;
            this.ja[(index == -1) ? this.ja.length : index] = value;
            return this;
        },

        /** @inheritDoc */
        putInt: function putInt(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            if (typeof value !== 'number') value = 0;
            this.ja[(index == -1) ? this.ja.length : index] = Math.floor(value) & 0xFFFFFFFF;
            return this;
        },

        /** @inheritDoc */
        putLong: function putLong(final int index, final long value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            if (typeof value !== 'number') value = 0;
            this.ja[(index == -1) ? this.ja.length : index] = Math.floor(value);
            return this;
        },

        /** @inheritDoc */
        putMap: function putMap(index, value) {
            if (index < -1)
                throw new RangeError("MslArray[" + index + "] is negative.");
            var o = (value instanceof Object) ? new JsonMslObject(value) : null;
            this.ja[(index == -1) ? this.ja.length : index] = o;
            return this;
        },

        /** @inheritDoc */
        remove: function remove(index) {
            if (index < 0 || index >= this.ja.length)
                throw new RangeError("MslArray[" + index + "] is negative or exceeds array length.");
            var o = this.opt(index);
            this.ja.splice(index, 1);
            return o;
        },

        /** @inheritDoc */
        getCollection: function getCollection() {
            return this.ja.slice();
        },

        /** @inheritDoc */
        getEncoded: function getEncoded() {
            return textEncoding$getBytes(JSON.stringify(this.ja),  MslConstants$DEFAULT_CHARSET);
        },
        
        /** @inheritDoc */
        toJSON: function toJSON() {
            return this.ja;
        },
    });
})();