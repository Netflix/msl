/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
 * A filter stream factory provides filter input stream and filter output
 * stream instances.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
	var FilterStreamFactory = module.exports = Class.create({
	    /**
	     * Return a new input stream that has the provided input stream as its
	     * backing source. If no filtering is desired then the original input
	     * stream must be returned.
	     *
	     * @param {InputStream} input the input stream to wrap.
	     * @return {InputStream} a new filter input stream backed by the provided input stream or
	     *         the original input stream..
	     */
	    getInputStream: function(input) {},
	
	    /**
	     * Return a new output stream that has the provided output stream as its
	     * backing destination. If no filtering is desired then the original output
	     * stream must be returned.
	     *
	     * @param {OutputStream} output the output stream to wrap.
	     * @return {OutputStream} a new filter output stream backed by the provided output stream
	     *         or the original output stream.
	     */
	    getOutputStream: function(output) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('FilterStreamFactory'));