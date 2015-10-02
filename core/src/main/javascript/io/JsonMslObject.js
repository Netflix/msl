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
 * <p>A {@code MslObject} that encodes its data as JSON.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var JsonMslObject;

(function() {
    "use strict";
    
    /**
     * Escape a string to be output as a single line of text.
     * 
     * @param s the string.
     * @returns the escaped string.
     */
    function quote(s) {
        var json = JSON.stringify(s);
        return json
            .replace(/[\"]/g, '\\"')
            .replace(/[\\]/g, '\\\\')
            .replace(/[\/]/g, '\\/')
            .replace(/[\b]/g, '\\b')
            .replace(/[\f]/g, '\\f')
            .replace(/[\n]/g, '\\n')
            .replace(/[\r]/g, '\\r')
            .replace(/[\t]/g, '\\t');
    }
    
    /**
     * Return a shallow copy of an object. This identifies properties to clone
     * using {@code hasOwnProperty}.
     * 
     * @param {Object} o the object to clone.
     * @returns {Object} the cloned object.
     */
    function cloneObject(o) {
        var co = {};
        for (var prop in o) {
            if (o.hasOwnProperty(prop)) {
                co[prop] = o[prop];
            }
        }
        return co;
    }
    
    JsonMslObject = MslObject.extend({
        /**
         * <p>Create a new empty {@code MslObject}.</p>
         * 
         * <p>If a source object map or an encoded representation is provided
         * then the object will be populated accordingly.</p>
         * 
         * @param {{Object.<String,*>|Uint8Array}=} source optional object map
         *        or encoded data.
         * @throws MslEncoderException if the data is malformed or invalid.
         * @see #getEncoded(
         */
        init: function init(source) {
            var jo = {};
            if (source instanceof Object) {
                jo = cloneObject(source);
            } else if (source instanceof Uint8Array) {
                var json = textEncoding$getString(source, MslConstants$DEFAULT_CHARSET);
                var decoded = JSON.parse(json);
                if (!(decoded instanceof Object))
                    throw new MslEncoderException("Invalid JSON object encoding.");
                jo = decoded;
            } catch (e) {
                throw new MslEncoderException("Invalid JSON object encoding.", e);
            }
            
            // The properties.
            var props = 
                jo: { value: jo, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        get: function get(key) {
            if (!key)
                throw new TypeError("Null key.");
            if (this.jo[key] === undefined)
                throw new MslEncoderException("MslObject[" + quote(key) + "] not found.");
            var o = this.jo[key];
            if (o instanceof Object)
                return new JsonMslObject(o);
            if (o instanceof Array)
                return new JsonMslArray(o);
            return o;
        },
    
        /** @inheritDoc */
        getBoolean: function getBoolean(key) {
            if (!key)
                throw new TypeError("Null key.");
            var b = this.jo[key];
            if (typeof b === 'boolean') return b;
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a boolean.");
        },
        
        /** @inheritDoc */
        getBytes: function getBytes(key) {
            if (!key)
                throw new TypeError("Null key.");
            var b64 = this.jo[key];
            if (typeof b64 === 'string') {
                try {
                    return base64$decode(b64);
                } catch (e) {
                    throw new MslEncoderException("MslObject[" + quote(key) + "] is not binary data.", e);
                }
            }
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not binary data.");
        },
    
        /** @inheritDoc */
        getDouble: function getDouble(key) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number')
                return x;
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a number.");
        }
    
        /** @inheritDoc */
        getInt: function getInt(key) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number')
                return Math.floor(x) & 0xFFFFFFFF;
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a number.");
        },
    
        /** @inheritDoc */
        getMslArray: function getMslArray(key) {
            if (!key)
                throw new TypeError("Null key.");
            var a = this.jo[key];
            if (a instanceof Array)
                return new JsonMslArray(a);
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a MslArray.");
        }
    
        /** @inheritDoc */
        getMslObject: function getMslObject(key) {
            if (!key)
                throw new TypeError("Null key.");
            var o = this.jo[key];
            if (o instanceof Object)
                return new JsonMslObject(o);
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a MslObject.");
        }
    
        /** @inheritDoc */
        getLong: function getLong(key) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number')
                return Math.floor(x);
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a number.");
        },
    
        /** @inheritDoc */
        getString: function getString(key) {
            if (!key)
                throw new TypeError("Null key.");
            var s = this.jo[key];
            if (typeof s === 'string')
                return s;
            throw new MslEncoderException("MslObject[" + quote(key) + "] is not a string.");
        },
    
        /** @inheritDoc */
        has: function has(key) {
            if (!key)
                throw new TypeError("Null key.");
            return this.jo[key] !== undefined;
        },
    
        /** @inheritDoc */
        opt: function opt(key) {
            if (!key)
                throw new TypeError("Null key.");
            var o = this.jo[key];
            if (o instanceof Object)
                return new JsonMslObject(o);
            if (o instanceof Array)
                return new JsonMslArray(o);
            return o;
        },
    
        /** @inheritDoc */
        optBoolean: function optBoolean(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var b = this.jo[key];
            if (typeof b === 'boolean') return b;
            if (typeof defaultValue === 'boolean') return defaultValue;
            return false;
        },
        
        /** @inheritDoc */
        optBytes: function optBytes(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var b64 = this.jo[key];
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
        optDouble: function optDouble(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number') return x;
            return (typeof defaultValue === 'number') ? defaultValue : Number.NaN;
        },
    
        /** @inheritDoc */
        optInt: function optInt(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number') return Math.floor(x) & 0xFFFFFFFF;
            return (typeof defaultValue === 'number') ? defaultValue : 0;
        },
    
        /** @inheritDoc */
        optMslArray: function optMslArray(key) {
            if (!key)
                throw new TypeError("Null key.");
            var a = this.jo[key];
            return (a instanceof Array) ? new JsonMslArray(a) : null;
        },
    
        /** @inheritDoc */
        optMslObject: function optMslObject(key) {
            if (!key)
                throw new TypeError("Null key.");
            var o = this.jo[key];
            return (o instanceof Object) ? new JsonMslObject(o) : null;
        },
    
        /** @inheritDoc */
        optLong: function optLong(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var x = this.jo[key];
            if (typeof x === 'number') return Math.floor(x);
            return (typeof defaultValue === 'number') ? defaultValue : 0;
        },
    
        /** @inheritDoc */
        optString: function optString(key, defaultValue) {
            if (!key)
                throw new TypeError("Null key.");
            var s = this.jo[key];
            if (typeof s === 'string') return s;
            return (typeof defaultValue === 'string') ? defaultValue : "";
        },
    
        /** @inheritDoc */
        put: function put(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            this.jo[key] = value;
            return this;
        },
    
        /** @inheritDoc */
        putBoolean: function putBoolean(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            if (typeof value !== 'boolean') value = false;
            this.jo[key] = value;
            return this;
        },
        
        /** @inheritDoc */
        putBytes: function putBytes(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            var b64 = (value instanceof Uint8Array) ? base64$encode(value) : null;
            this.jo[key] = b64;
            return this;
        },
    
        /** @inheritDoc */
        putCollection: function putCollection(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            var a = (value instanceof Array) ? new JsonMslArray(value) : null;
            this.jo[key] = a;
            return this;
        },
    
        /** @inheritDoc */
        putDouble: function putDouble(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            if (typeof value !== 'number') value = Number.NaN;
            this.jo[key] = value;
            return this;
        },
    
        /** @inheritDoc */
        putInt: function putInt(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            if (typeof value !== 'number') value = 0;
            this.jo[key] = Math.floor(value) & 0xFFFFFFFF;
            return this;
        },
    
        /** @inheritDoc */
        putLong: function putLong(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            if (typeof value !== 'number') value = 0;
            this.jo[key] = Math.floor(value);
            return this;
        },
    
        /** @inheritDoc */
        putMap: function putMap(key, value) {
            if (!key)
                throw new TypeError("Null key.");
            var o = (value instanceof Object) ? new JsonMslObject(value) : null;
            this.jo[key] = o;
            return this;
        },
    
        /** @inheritDoc */
        remove: function remove(key) {
            if (!key)
                throw new TypeError("Null key.");
            var o = this.opt(key);
            delete this.jo[key];
            return o;
        },
    
        /** @inheritDoc */
        getMap: function getMap() {
            return cloneObject(this.jo);
        },
    
        /** @inheritDoc */
        getEncoded: function getEncoded() {
            return textEncoding$getBytes(JSON.stringify(this.jo), MslConstants$DEFAULT_CHARSET);
        },
        
        /** @inheritDoc */
        toJSON: function toJSON() {
            return this.jo;
        },
    });
})();