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
 * <p>A MSL user. The {@link #equals(Object)} and {@link #uniqueKey()} methods
 * must be implemented.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
		
	var MslUser = module.exports = Class.create({
	    /**
	     * <p>Returns a serialized data encoding of the MSL user. This is the value
	     * that will be used by the MSL stack during transport and to reconstruct
	     * the MSL user instance.</p>
	     * 
	     * @return {string} the MSL user encoding.
	     */
	    getEncoded: function() {},
	
	    /**
	     * <p>Compares this object against the provided object. This method must
	     * return true if the provided object is a {@code MslUser} referencing the
	     * same MSL user.</p>
	     * 
	     * @param {?} obj the object with which to compare.
	     * @return {@code true} if the object is a {@code MslUser} that references
	     *         the same MSL user.
	     * @see #uniqueKey()
	     */
	    equals: function(that) {},
	
	    /**
	     * @return {string} a string that uniquely identifies this MSL user.
	     * @see #equals(that)
	     */
	    uniqueKey: function() {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslUser'));