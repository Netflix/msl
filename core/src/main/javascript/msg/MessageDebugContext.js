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
 * <p>A message debug context is used to provide debugging callbacks to
 * {@code MslControl}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @interface
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
		
	var MessageDebugContext = module.exports = Class.create({
	    /**
	     * Called just prior to sending a message with the message header or error
	     * header that will be sent. An error may occur preventing successful
	     * transmission of the header after this method is called.
	     * 
	     * @param {Header} header message header or error header. 
	     */
	    sentHeader: function(header) {},
	    
	    /**
	     * Called just after receiving a message, before performing additional
	     * validation, with the message header or error header.
	     * 
	     * @param {Header} header message header or error header.
	     */
	    receivedHeader: function(header) {}
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageDebugContext'));