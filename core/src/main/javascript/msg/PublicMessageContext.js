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
 * messages that do not require contents to be encrypted, only to be integrity
 * protected. If encryption is possible the message contents will be
 * encrypted.</p>
 * 
 * <p>Example uses of the public message context would be for the broadcast of
 * authenticated public announcements or the transmission of information that
 * is useless after a short period of time.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";

	var MessageContext = require('../msg/MessageContext.js');
	
	var PublicMessageContext = module.exports = MessageContext.extend({
	    /** @inheritDoc */
	    isEncrypted: function isEncrypted() {
	        return false;
	    },
	    
	    /** @inheritDoc */
	    isIntegrityProtected: function isIntegrityProtected() {
	        return true;
	    },
	    
	    /** @inheritDoc */
	    isNonReplayable: function isNonReplayable() {
	        return false;
	    }
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('PublicMessageContext'));