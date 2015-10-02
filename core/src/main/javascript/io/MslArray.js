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
var MslArray;

(function() {
    "use strict";

    /**
     * @interface
     */
    MslArray = util.Class.create({
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {?} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        get: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {boolean} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getBoolean: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {Uint8Array} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getBytes: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getDouble: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getInt: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {MslArray} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getMslArray: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {MslObject} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getMslObject: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {number} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getLong: function(index) {},
    
        /**
         * Return the value associated with an index.
         * 
         * @param {number} index the index.
         * @return {string} the value.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         * @throws MslEncoderException if the value is {@code null}.
         */
        getString: function(index) {},
    
        /**
         * Return true if the value at the index is {@code null}.
         * 
         * @param {number} index the index.
         * @return {boolean} true if the value is null.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        isNull: function(index) {},
        
        /**
         * Return the number of elements in the array, including {@code null}
         * values.
         * 
         * @return {number} the array size.
         */
        length() {},
        
        /**
         * Return the value at the index.
         * 
         * @param {number} index the index.
         * @return {?} the value. May be {@code null}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        opt: function(index) {},
        
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
        optBoolean: function(index, defaultValue) {},
    
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
        optBytes(index, defaultValue) {},
        
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
        optDouble: function(index, defaultValue) {},
        
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
        optInt: function(index, defaultValue) {},
    
        /**
         * Return the {@code MslArray} at the index or {@code null} if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @return {MslArray} the {@code MslArray}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optMslArray: function(index) {},
    
        /**
         * Return the {@code MslObject} at the index or {@code null} if the value
         * is not of the correct type.
         * 
         * @param {number} index the index.
         * @return {MslObject} the {@code MslObject}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        optMslObject: function(index) {},
        
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
        optLong: function(index, defaultValue) {},
        
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
        optString: function(index, defaultValue) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {?} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        put: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {boolean} value the value.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putBoolean: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Uint8Array} value the value.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putBytes: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. The
         * collection of elements will be transformed into a {@code MslArray}. If
         * the index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Array.<?>} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putCollection: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putDouble: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putInt: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. If the
         * index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {number} value the value.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putLong: function(index, value) {},
        
        /**
         * Put or replace a value in the {@code MslArray} at the index. The map of
         * strings onto objects will be transformed into a {@code MslObject}. If
         * the index exceeds the length, null elements will be added as necessary.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @param {Object.<String,?>} value the value. May be {@code null}.
         * @return {MslArray} this.
         * @throws RangeError if the index is less than -1.
         */
        putMap: function(index, value) {},
        
        /**
         * Remove an element at the index. This decreases the length by one.
         * 
         * @param {number} index the index. -1 for the end of the array.
         * @return {?} the removed value. May be {@code null}.
         * @throws RangeError if the index is negative or
         *         exceeds the number of elements in the array.
         */
        remove: function(index) {},
    
        /**
         * Return a collection of the {@code MslArray} contents.
         * 
         * @return {Array.<?>} the collection of {@code MslArray} contents.
         */
        getCollection: function() {},
        
        /**
         * Encode the {@code MslArray} into its binary form.
         * 
         * @return {Uint8Array} the encoded form of the {@code MslArray}.
         * @throws MslEncoderException if there is an error generating the encoding.
         */
        getEncoded: function() {},
    });
})();
