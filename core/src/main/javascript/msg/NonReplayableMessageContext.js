/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * <p>A message context implementation that can be extended for use with
 * messages that cannot be replayed. This also carries the security properties
 * of encryption and integrity protection.</p>
 * 
 * <p>Example uses of the non-replayable message context would be for the
 * transmission of financial transactions or to grant access to restricted
 * resources where a repeat transmission may result in incorrect data or
 * abuse.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";

	var MessageContext = require('../msg/MessageContext.js');
	
	var NonReplayableMessageContext = module.exports = MessageContext.extend({
	    /** @inheritDoc */
	    isEncrypted: function isEncrypted() {
	        return true;
	    },
	    
	    /** @inheritDoc */
	    isIntegrityProtected: function isIntegrityProtected() {
	        return true;
	    },
	    
	    /** @inheritDoc */
	    isNonReplayable: function isNonReplayable() {
	        return true;
	    }
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('NonReplayableMessageContext'));