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
 * <p>A MSL store where all operations are no-ops.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @implements {MslStore}
 */
(function(require, module) {
	"use strict";
	
	var MslStore = require('../util/MslStore.js');
	var MslException = require('../MslException.js');
	var MslError = require('../MslError.js');
	
	var NullMslStore = module.exports = MslStore.extend({
	    /** @inheritDoc */
	    setCryptoContext: function setCryptoContext(masterToken, cryptoContext) {},
	
	    /** @inheritDoc */
	    getMasterToken: function getMasterToken() { return null; },
	    
	    /** @inheritDoc */
	    getNonReplayableId: function getNonReplayableId(masterToken) { return 1; },
	
	    /** @inheritDoc */
	    getCryptoContext: function getCryptoContext(masterToken) { return null; },
	
	    /** @inheritDoc */
	    removeCryptoContext: function removeCryptoContext(masterToken) {},
	
	    /** @inheritDoc */
	    clearCryptoContexts: function clearCryptoContexts() {},
	
	    /** @inheritDoc */
	    addUserIdToken: function addUserIdToken(userId, userIdToken) {},
	
	    /** @inheritDoc */
	    getUserIdToken: function getUserIdToken(userId) { return null; },
	
	    /** @inheritDoc */
	    removeUserIdToken: function removeUserIdToken(userIdToken) {},
	
	    /** @inheritDoc */
	    clearUserIdTokens: function clearUserIdTokens() {},
	
	    /** @inheritDoc */
	    addServiceTokens: function addServiceTokens(tokens) {},
	
	    /** @inheritDoc */
	    getServiceTokens: function getServiceTokens(masterToken, userIdToken) {
	        // Validate arguments.
	        if (userIdToken) {
	            if (!masterToken)
	                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL);
	            if (!userIdToken.isBoundTo(masterToken))
	                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.mtSerialNumber + "; mt " + masterToken.serialNumber);
	        }
	        return [];
	    },
	
	    /** @inheritDoc */
	    removeServiceTokens: function removeServiceTokens(name, masterToken, userIdToken) {
	        // Validate arguments.
	        if (userIdToken && masterToken && !userIdToken.isBoundTo(masterToken))
	            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.masterTokenSerialNumber + "; mt " + masterToken.serialNumber);
	    },
	
	    /** @inheritDoc */
	    clearServiceTokens: function clearServiceTokens() {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('NullMslStore'));