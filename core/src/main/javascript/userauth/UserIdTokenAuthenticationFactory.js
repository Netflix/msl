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
 * User ID token-based user authentication factory.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	const UserAuthenticationFactory = require('../userauth/UserAuthenticationFactory.js');
	const UserAuthenticationScheme = require('../userauth/UserAuthenticationScheme.js');
	const UserIdTokenAuthenticationData = require('../userauth/UserIdTokenAuthenticationData.js');
	const MslInternalException = require('../MslInternalException.js');
	const MslUserAuthException = require('../MslUserAuthException.js');
	const MslError = require('../MslError.js');
	
	var UserIdTokenAuthenticationFactory = module.exports = UserAuthenticationFactory.extend({
	    /**
	     * Construct a new user ID token-based user authentication factory.
	     *
	     * @param {AuthenticationUtils} authutils authentication utilities.
	     */
	    init: function init(authutils) {
	        init.base.call(this, UserAuthenticationScheme.USER_ID_TOKEN);
	
	        // The properties.
	        var props = {
	            _authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /** @inheritDoc */
	    createData: function createData(ctx, masterToken, userAuthMo, callback) {
	        UserIdTokenAuthenticationData.parse(ctx, userAuthMo, callback);
	    },
	
	    /** @inheritDoc */
	    authenticate: function authenticate(ctx, identity, data, userIdToken) {
	        // Make sure we have the right kind of user authentication data.
	        if (!(data instanceof UserIdTokenAuthenticationData))
	            throw new MslInternalException("Incorrect authentication data type " + data + ".");
	        var uita = data;
	
	        // Verify the scheme is permitted.
	        if(!this._authutils.isSchemePermitted(identity, this.scheme))
	            throw new MslUserAuthException(MslError.USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserIdToken(data);
	
	        // Extract and check master token.
	        var uitaMasterToken = uita.masterToken;
	        var uitaIdentity = uitaMasterToken.identity;
	        if (!uitaIdentity)
	            throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED).setUserIdToken(uita);
	        if (identity != uitaIdentity)
	            throw new MslUserAuthException(MslError.USERAUTH_ENTITY_MISMATCH, "entity identity " + identity + "; uad identity " + uitaIdentity).setUserIdToken(uita);
	
	        // Authenticate the user.
	        var uitaUserIdToken = uita.userIdToken;
	        var user = uitaUserIdToken.user;
	        if (!user)
	            throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED).setUserIdToken(uita);
	
	        // Verify the scheme is still permitted.
	        if (!this._authutils.isSchemePermitted(identity, user, this.scheme))
	            throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserIdToken(data);
	
	        // If a user ID token was provided validate the user identities.
	        if (userIdToken) {
	            var uitUser = userIdToken.user;
	            if (!user.equals(uitUser))
	                throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser);
	        }
	
	        // Return the user.
	        return user;
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserIdTokenAuthenticationFactory'));
