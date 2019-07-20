/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
(function(require, module) {
	"use strict";
	
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslObject = require('../io/MslObject.js');
	var MslArray = require('../io/MslArray.js');
	var MslEncodable = require('../io/MslEncodable.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var Arrays = require('../util/Arrays.js');
    
    /**
     * Create a MSL array from a collection of objects that are either one of
     * the accepted types: <code>Boolean</code>, <code>Byte[]</code>,
     * <code>MslArray</code>, <code>MslObject</code>, <code>Number</code>,
     * <code>String</code>, <code>null</code>, or turn any
     * <code>MslEncodable</code> into a <code>MslObject</code>.
     * 
     * @param {MslContext} ctx MSL context.
     * @param {MslEncoderFormat} format MSL encoder format.
     * @param {Array<*>} c a collection of MSL encoding-compatible objects.
     * @param {{result: function(MslArray), error: function(Error)}} callback
     *        the callback that will receive the constructed MSL array or any
     *        thrown exceptions.
     * @throws MslEncoderException if a <code>MslEncodable</code> cannot be
     *         encoded properly or an unsupported object is encountered.
     */
    var MslEncoderUtils$createArray = function MslEncoderUtils$createArray(ctx, format, c, callback) {
    	function add(encoder, array, i, callback) {
	    	AsyncExecutor(callback, function() {
	    		if (i >= c.length) return array;
	    		var o = c[i];
	    		if (o instanceof Boolean ||
	    			typeof o === 'boolean' ||
	    			o instanceof Uint8Array ||
	    			o instanceof Number ||
	    			typeof o === 'number' ||
	    			o instanceof MslObject ||
	    			o instanceof MslArray ||
	    			o instanceof String ||
	    			typeof o === 'string' ||
	    			(o instanceof Object && o.constructor === Object) ||
	    			o instanceof Array ||
	    			o === null)
	    		{
	    			array.put(-1, o);
	    			add(encoder, array, i+1, callback);
	    		} else if (o instanceof MslEncodable) {
	    			var me = o;
	    			me.toMslEncoding(encoder, format, {
	    				result: function(encode) {
	    					AsyncExecutor(callback, function() {
	    						var mo = encoder.parseObject(encode);
	    						array.put(-1, mo);
	    						add(encoder, array, i+1, callback);
	    					});
	    				},
	    				error: callback.error,
	    			});
	    		} else {
	    			throw new MslEncoderException("Class " + typeof o + " is not MSL encoding-compatible.");
	    		}
	    	});
    	}
    	
    	AsyncExecutor(callback, function() {
    		var encoder = ctx.getMslEncoderFactory();
    		var array = encoder.createArray();
    		add(encoder, array, 0, callback);
    	});
    };
    
    /**
     * Performs a deep comparison of two MSL objects for equivalence. MSL
     * objects are equivalent if they have the same name/value pairs. Also, two
     * MSL object references are considered equal if both are null.
     * 
     * @param {?MslObject} mo1 first MSL object. May be null.
     * @param {?MslObject} mo2 second MSL object. May be null.
     * @return {boolean} true if the MSL objects are equivalent.
     * @throws MslEncoderException if there is an error parsing the data.
     */
    var MslEncoderUtils$equalObjects = function MslEncoderUtils$equalObjects(mo1, mo2) {
        // Equal if both null or the same object.
        if (mo1 === mo2)
            return true;
        // Not equal if only one of them is null.
        if (mo1 == null || mo2 == null)
            return false;
        
        // Check the children names. If there are no names, the MSL object is
        // empty.
        var names1 = mo1.getKeys();
        var names2 = mo2.getKeys();
        // Continue if the same object.
        if (names1 !== names2) {
	        // Not equal if only one of them is null or of different length.
	        if (names1 == null || names2 == null || names1.length != names2.length)
	            return false;
	        // Not equal if the sets are not equal.
	        if (!Arrays.containEachOther(names1, names2))
	            return false;
        }
        
        // Bail on the first child element whose values are not equal.
        for (var i = 0; i < names1.length; ++i) {
            var name = names1[i];
            var o1 = mo1.opt(name);
            var o2 = mo2.opt(name);
            // Equal if both null or the same object.
            if (o1 === o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            // byte[] may be represented differently, so we have to compare by
            // accessing directly. This isn't perfect but works for now.
            if (o1 instanceof Uint8Array || o2 instanceof Uint8Array) {
                var b1 = mo1.getBytes(name);
                var b2 = mo2.getBytes(name);
                if (!Arrays.equal(b1, b2))
                    return false;
            } else if (o1 instanceof MslObject && o2 instanceof MslObject) {
                if (!MslEncoderUtils$equalObjects(o1, o2))
                    return false;
            } else if (o1 instanceof MslArray && o2 instanceof MslArray) {
                if (!MslEncoderUtils$equalArrays(o1, o2))
                    return false;
            } else {
                if (typeof o1 !== typeof o2)
                    return false;
                if (o1 != o2)
                    return false;
            }
        }
        
        // All name/value pairs are equal.
        return true;
    };
    
    /**
     * Performs a deep comparison of two MSL arrays for equality. Two MSL
     * arrays are considered equal if both arrays contain the same number of
     * elements, and all corresponding pairs of elements in the two arrays are
     * equal. In other words, two MSL arrays are equal if they contain the
     * same elements in the same order. Also, two MSL array references are
     * considered equal if both are null.
     * 
     * @param {?MslArray} ma1 first MSL array. May be null.
     * @param {?MslArray} ma2 second MSL array. May be null.
     * @return true if the MSL arrays are equal.
     * @throws MslEncoderException if there is an error parsing the data.
     */
    var MslEncoderUtils$equalArrays = function MslEncoderUtils$equalArrays(ma1, ma2) {
        // Equal if both null or the same object.
        if (ma1 === ma2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ma1 == null || ma2 == null || ma1.size() != ma2.size())
            return false;
        
        // Bail on the first elements whose values are not equal.
        for (var i = 0; i < ma1.size(); ++i) {
            var o1 = ma1.opt(i);
            var o2 = ma2.opt(i);
            // Equal if both null or the same object.
            if (o1 === o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            // byte[] may be represented differently, so we have to compare by
            // accessing directly. This isn't perfect but works for now.
            if (o1 instanceof Uint8Array || o2 instanceof Uint8Array) {
                var b1 = ma1.getBytes(i);
                var b2 = ma2.getBytes(i);
                if (!Arrays.equal(b1, b2))
                    return false;
            } else if (o1 instanceof MslObject && o2 instanceof MslObject) {
                if (!MslEncoderUtils$equalObjects(o1, o2))
                    return false;
            } else if (o1 instanceof MslArray && o2 instanceof MslArray) {
                if (!MslEncoderUtils$equalArrays(o1, o2))
                    return false;
            } else {
                if (typeof o1 !== typeof o2)
                    return false;
                if (o1 != o2)
                    return false;
            }
        }
        
        // All values are equal.
        return true;
    };
    
    /**
     * Performs a shallow comparison of two MSL arrays for set equality. Two
     * MSL arrays are considered set-equal if both arrays contain the same
     * number of elements and all elements found in one array are also found in
     * the other. In other words, two MSL arrays are set-equal if they contain
     * the same elements in the any order. Also, two MSL array references are
     * considered set-equal if both are null.
     * 
     * @param {MslArray} ma1 first MSL array. May be {@code null}.
     * @param {MslArray} ma2 second MSL array. May be {@code null}.
     * @return {boolean} true if the MSL arrays are set-equal.
     * @throws MslEncoderException if there is an error parsing the data.
     */
    var MslEncoderUtils$equalSets = function MslEncoderUtils$equalSets(ma1, ma2) {
        // Equal if both null or the same object.
        if (ma1 == ma2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ma1 == null || ma2 == null || ma1.size() != ma2.size())
            return false;
        
        // Compare as sets.
        var s1 = [];
        var s2 = [];
        for (var i = 0; i < ma1.size(); ++i) {
            s1[i] = ma1.opt(i);
            s2[i] = ma2.opt(i);
        }
        return Arrays.containEachOther(s1, s2);
    };
    
    /**
     * Merge two MSL objects into a single MSL object. If the same key is
     * found in both objects, the second object's value is used. The values are
     * copied by reference so this is a shallow copy.
     * 
     * @param {?MslObject} mo1 first MSL object. May be null.
     * @param {?MslObject} mo2 second MSL object. May be null.
     * @return {?MslObject} the merged MSL object or null if both arguments are null.
     * @throws MslEncoderException if a value in one of the arguments is
     *         invalid—this should not happen.
     */
    var MslEncoderUtils$merge = function MslEncoderUtils$merge(mo1, mo2) {
        // Return null if both objects are null.
        if (!mo1 && !mo2)
            return null;

        // Make a copy of the first object, or create an empty object.
        var mo = (mo1)
            ? new MslObject(mo1.getMap())
            : new MslObject();

        // If the second object is null, we're done and just return the copy.
        if (!mo2)
            return mo;
        
        // Copy the contents of the second object into the final object.
        var keys = mo2.getKeys();
        for (var i = 0; i < keys.length; ++i) {
        	var key = keys[i];
            mo.put(key, mo2.get(key));
        }
        return mo;
    };
    
    // Exports.
    module.exports.createArray = MslEncoderUtils$createArray;
    module.exports.equalObjects = MslEncoderUtils$equalObjects;
    module.exports.equalArrays = MslEncoderUtils$equalArrays;
    module.exports.equalSets = MslEncoderUtils$equalSets;
    module.exports.merge = MslEncoderUtils$merge;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslEncoderUtils'));