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
 * This class should be used by trusted network clients for the token factory.
 * Since trusted network clients do not issue tokens the majority of these
 * methods either return under the assumption everything should be accepted or
 * trusted, or throw exceptions if the operation should never occur.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var TokenFactory = require('../tokens/TokenFactory.js');
	var MslInternalException = require('../MslInternalException.js');
	
	var ClientTokenFactory = module.exports = TokenFactory.extend({
	    /** @inheritDoc */
	    isMasterTokenRevoked: function isMasterTokenRevoked(ctx, masterToken, callback) {
	        callback.result(null);
	    },
	    
	    /** @inheritDoc */
	    acceptNonReplayableId: function acceptNonReplayableId(ctx, masterToken, nonReplayableId, callback) {
	        callback.result(null);
	    },
	    
	    /** @inheritDoc */
	    createMasterToken: function createMasterToken(ctx, entityToken, encryptionKey, hmacKey, issuerData, callback) {
	        callback.error(new MslInternalException("Creating master tokens is unsupported by the token factory."));
	    },
	
	    /** @inheritDoc */
	    isMasterTokenRenewable: function isMasterTokenRenewable(ctx, masterToken, callback) {
	        callback.result(null);
	    },
	    
	    /** @inheritDoc */
	    renewMasterToken: function renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, issuerData, callback) {
	        callback.error(new MslInternalException("Renewing master tokens is unsupported by the token factory."));
	    },
	
	    /** @inheritDoc */
	    isUserIdTokenRevoked: function isUserIdTokenRevoked(ctx, masterToken, userIdToken, callback) {
	        callback.result(null);
	    },
	    
	    /** @inheritDoc */
	    createUserIdToken: function createUserIdToken(ctx, user, masterToken, callback) {
	        callback.error(new MslInternalException("Creating user ID tokens is unsupported by the token factory."));
	    },
	
	    /** @inheritDoc */
	    renewUserIdToken: function renewUserIdToken(ctx, userIdToken, masterToken, callback) {
	        callback.error(new MslInternalException("Renewing user ID tokens is unsupported by the token factory."));
	    },
	    
	    /** @inheritDoc */
	    createUser: function createUser(ctx, userdata, callback) {
	        callback.error(new MslInternalException("Creating users is unsupported by the token factory."));
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ClientTokenFactory'));