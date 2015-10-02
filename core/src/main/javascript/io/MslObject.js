/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
var MslObject;

(function() {
    "use strict";

    /**
     * @interface
     */
    MslObject = util.Class.create({
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {?} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value or the value
         *         is {@code null}.
         */
        get: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {boolean} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getBoolean: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getDouble: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getInt: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {MslArray} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getMslArray: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {MslObject} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getMslObject: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getLong: function(key) {},
        
        /**
         * Return the value associated with the specified key.
         * 
         * @param {string} key the key.
         * @return {string} the value.
         * @throws TypeError if the key is {@code null}.
         * @throws MslEncoderException if there is no associated value of the
         *         proper type or the value is {@code null}.
         */
        getString: function(key) {},
    
        /**
         * Return true if the specified key exists. The value may be {@code null}.
         * 
         * @param {string} key the key.
         * @throws TypeError if the key is {@code null}.
         */
        has: function(key) {},
    
        /**
         * Return the value associated with the specified key or {@code null} if
         * the key is unknown.
         * 
         * @param {string} key the key.
         * @return {?} the value. May be {@code null}.
         * @throws TypeError if the key is {@code null}.
         */
        opt: function(key) {},
    
        /**
         * Return the value associated with the specified key, or {@code false}
         * or the default value if the key is unknown or the value is not of
         * the correct type.
         * 
         * @param {string} key the key.
         * @param {boolean=} defaultValue the optional default value.
         * @return {boolean} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optBoolean: function(key, defaultValue) {},

        /**
         * Return the value associated with the specified key, or an empty byte
         * array or the default value if the key is unknown or the value is not
         * of the correct type.
         * 
         * @param {string} key the key.
         * @param {Uint8Array=} defaultValue the default value.
         * @return {Uint8Array} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optBytes: function(key, defaultValue) {},
    
        /**
         * Return the value associated with the specified key, or {@code NaN}
         * or the default value if the key is unknown or the value is not of
         * the　correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optDouble: function(key, defaultValue) {},
    
        /**
         * Return the value associated with the specified key, or zero or
         * the default value if the key is unknown or the value is not of the
         * correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optInt: function(key, defaultValue) {},
        
        /**
         * Return the {@code MslArray} associated with the specified key or
         * {@code null} if the key is unknown or the value is not of the correct
         * type.
         * 
         * @param {string} key the key.
         * @return {MslArray} the {@code MslArray}.
         * @throws TypeError if the key is {@code null}.
         */
        optMslArray: function(key) {},
    
        /**
         * Return the {@code MslObject} associated with the specified key or
         * {@code null} if the key unknown or the value is not of the correct type.
         * 
         * @param {string} key the key.
         * @return {MslObject} the {@code MslObject}.
         * @throws TypeError if the key is {@code null}.
         */
        optMslObject: function(key) {},
    
        /**
         * Return the value associated with the specified key, or zero or
         * the default value if the key is unknown or the value is not of the
         * correct type.
         * 
         * @param {string} key the key.
         * @param {number=} defaultValue the optional default value.
         * @return {number} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optLong: function(key, defaultValue) {},
    
        /**
         * Return the value associated with the specified key, or the empty
         * string or the default value if the key is unknown or the value is
         * not of the correct type.
         * 
         * @param {string} key the key.
         * @param {string=} defaultValue the default value.
         * @return {string} the value.
         * @throws TypeError if the key is {@code null}.
         */
        optString: function(key, defaultValue) {},
        
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {?} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        put: function(key, value) {},
        
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {boolean} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putBoolean: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {Uint8Array} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putBytes: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. The collection of
         * elements will be transformed into a {@code MslArray}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {Array.<?>} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putCollection: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putDouble: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putInt: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {string} key the key.
         * @param {number} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putLong: function(key, value) {},
    
        /**
         * Put a key/value pair into the {@code MslObject}. The map of strings onto
         * objects will be transformed into a {@code MslObject}. If the value is
         * {@code null} the key will be removed.
         * 
         * @param {key} key the key.
         * @param {object} value the value. May be {@code null}.
         * @return {MslObject} this.
         * @throws TypeError if the key is {@code null}.
         */
        putMap(key, value) {},
        
        /**
         * Remove a key and its associated value from the {@code MslObject}.
         * 
         * @param {string} key the key.
         * @return {?} the removed value. May be {@code null}.
         * @throws TypeError if the key is {@code null}.
         */
        remove: function(key) {},
        
        /**
         * Return a map of the {@code MslObject} contents.
         * 
         * @return {object} the map of {@code MslObject} contents.
         */
        getMap: function() {},
        
        /**
         * Encode the {@code MslObject} into its binary form.
         * 
         * @return {Uint8Array} the encoded form of the {@code MslObject}.
         * @throws MslEncoderException if there is an error generating the encoding.
         */
        getEncoded: function() {},
    });
})();
