/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Utility methods for arrays.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	/**
	 * @param {(Uint8Array|Array.<number>)} a first array.
	 * @param {(Uint8Array|Array.<number>)} b second array.
	 * @return {boolean} true if the two arrays are equal.
	 */
	var Arrays$equal = function Arrays$equal(a, b) {
	    if (a === b) return true;
	    if (!a || !b || a.length != b.length) return false;
	    for (var i = 0; i < a.length; ++i) {
	        if (a[i] != b[i])
	            return false;
	    }
	    return true;
	};
	
	/**
	 * @param o {*} object to test.
	 * @returns {Boolean} true if the object is a Uint8Array.
	 */
	var Arrays$isUint8Array = function Arrays$isUint8Array(o) {
	    return o && o.constructor == Uint8Array;
	};
	
	/**
	 * @param {Uint8Array|Array.<number>} a the array to copy.
	 * @param {number=} off optional offset into a to start the copy from. If omitted
	 *        the copy will begin at the start of a. If negative the offset is
	 *        computed from the end of the array.
	 * @param {number=} len optional number of bytes to copy. If omitted the copy will
	 *        proceed until the end of a is hit. If larger than the number of bytes
	 *        in a, the result will be padded with zeros.
	 * @return {Uint8Array|Array.<number>} a shallow copy of the array.
	 */
	var Arrays$copyOf = function Arrays$copyOf(a, off, len) {
	    var b;
	
	    // The offset is not less than the length then throw an exception.
	    if (off >= a.length)
	        throw new RangeError('Array offset (' + off + ') must be less than array length (' + a.length + ').');
	
	    // If the offset is negative, the real offset is equal to the array length
	    // minus the offset.
	    if (off === undefined || off === null)
	        off = 0;
	    if (off < 0)
	        off = Math.max(0, a.length - off);
	
	    // Clamp the length based on the offset.
	    if (len === undefined || len === null)
	        len = a.length - off;
	
	    // Create the copy.
	    if (Arrays$isUint8Array(a))
	        b = new Uint8Array(len);
	    else if (Array.isArray(a))
	        b = new Array(len);
	    else
	        throw new TypeError('Cannot create an array copy of ' + a);
	
	    // Perform the copy.
	    var count = Math.min(len, a.length - off);
	    for (var i = 0; i < count; ++i)
	        b[i] = a[i + off];
	    return b;
	};
	
	/**
	 * @param {Uint8Array|Array.<number>} a the array to compute a hash code for.
	 * @return {number} the computed hash code.
	 */
	var Arrays$hashCode = function Arrays$hashCode(a) {
	    if (!(Arrays$isUint8Array(a)) && !(Array.isArray(a)))
	        throw new TypeError('Cannot compute the hash code of ' + a);
	    var result = 1;
	    for (var i = 0; i < a.length; ++i) {
	        var element = a[i];
	        if (typeof element !== 'number')
	            throw new TypeError('Cannot compute the hash code over non-numeric elements: ' + element);
	        result = (31 * result + element) & 0xFFFFFFFF;
	    }
	    return result;
	};
	
	/**
	 * Returns true if the first array contains all the elements of the second
	 * array, or the specified element. If b or the elements of b have a property
	 * {@code equals()} then that method will be used to check if an element in a
	 * is equal.
	 *
	 * @param {Array} a first array.
	 * @param {Array} b second array or single element.
	 * @return {boolean} true if a contains all the elements of b.
	 */
	var Arrays$contains = function Arrays$contains(a, b) {
	    if (a === b) return true;
	    if (!a || !b) return false;
	    if (!(b instanceof Array))
	        b = [b];
	    for (var i = 0; i < b.length; ++i) {
	        var bElem = b[i];
	        var found = false;
	        for (var j = 0; j < a.length; ++j) {
	            var aElem = a[j];
	            if ((bElem.equals && typeof bElem.equals === 'function' && bElem.equals(aElem)) ||
	                bElem == aElem)
	            {
	                found = true;
	                break;
	            }
	        }
	        if (!found)
	            return false;
	    }
	    return true;
	};
	
	/**
	 * Returns true if both arrays contain all the elements of the other array,
	 * irrespective of ordering. If the elements of have a property
	 * {@code equals()} then that method will be used to check if the elements are
	 * equal.
	 *
	 * @param {Array.<*>} a first array.
	 * @param {Array.<*>} b second array.
	 * @return {boolean} true if a contains all the elements of b and vice versa.
	 */
	var Arrays$containEachOther = function Arrays$containEachOther(a, b) {
	    return Arrays$contains(a, b) && (a.length == b.length || Arrays$contains(b, a));
	};
	
	/**
	 * Returns a new array containing the tokens of a plus the tokens of b,
	 * replacing and tokens in a with equal tokens in b.
	 *
	 * If a filter function is provided then only elements of b for which the
	 * function returns true will be included in the returned array. The filter
	 * function receives a single argument which is the element of b.
	 *
	 * @param {Array.<MasterToken>|Array.<UserIdToken>|Array.<ServiceToken>} a first array.
	 * @param {Array.<MasterToken>|Array.<UserIdToken>|Array.<ServiceToken>} b second array.
	 * @param {Function=} f optional filter function for adding elements of b.
	 * @returns {Array.<MasterToken>|Array.<UserIdToken>|Array.<ServiceToken>} combined array.
	 */
	var Arrays$combineTokens = function Arrays$combineTokens(a, b, f) {
	    if (!f) f = function(e) { return true; };
	    var map = {};
	    a.forEach(function(e) {
	        map[e.uniqueKey()] = e;
	    }, this);
	    b.forEach(function(e) {
	        if (f(e))
	            map[e.uniqueKey()] = e;
	    }, this);
	    var arr = [];
	    for (var key in map)
	        arr.push(map[key]);
	    return arr;
	};
	
	/**
	 * Concatenates array of Uint8Arrays into a new Uint8Array
	 *
	 * @param {Array.<Uint8Array>} arrays array of Uint8Array to merge
	 * @returns {Uint8Array} concatenated array
	 */
	var Arrays$concat = function Arrays$concat(arrays) {
	    var result,
	        i,
	        current,
	        l = arrays.length,
	        position = 0,
	        totalLength = 0;
	
	    for (i = 0; i < l; i++) {
	        totalLength += arrays[i].length;
	    }
	    result = new Uint8Array(totalLength);
	    for (i = 0; i < l; i++) {
	        current = arrays[i];
	        result.set(current, position);
	        position += current.length;
	    }
	    return result;
	};
	
	// Exports.
	module.exports.equal = Arrays$equal;
	module.exports.isUint8Array = Arrays$isUint8Array;
	module.exports.copyOf = Arrays$copyOf;
	module.exports.hashCode = Arrays$hashCode;
	module.exports.contains = Arrays$contains;
	module.exports.containEachOther = Arrays$containEachOther;
	module.exports.combineTokens = Arrays$combineTokens;
	module.exports.concat = Arrays$concat;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Arrays'));