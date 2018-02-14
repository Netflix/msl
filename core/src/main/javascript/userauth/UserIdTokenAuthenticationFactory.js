/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
    
    var UserAuthenticationFactory = require('../userauth/UserAuthenticationFactory.js');
    var UserAuthenticationScheme = require('../userauth/UserAuthenticationScheme.js');
    var UserIdTokenAuthenticationData = require('../userauth/UserIdTokenAuthenticationData.js');
    var MslInternalException = require('../MslInternalException.js');
    var MslUserAuthException = require('../MslUserAuthException.js');
    var MslError = require('../MslError.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslException = require('../MslException.js');
    
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
        authenticate: function authenticate(ctx, identity, data, userIdToken, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Make sure we have the right kind of user authentication data.
                if (!(data instanceof UserIdTokenAuthenticationData))
                    throw new MslInternalException("Incorrect authentication data type " + data + ".");
                var uitad = data;

                // Verify the scheme is permitted.
                if(!this._authutils.isSchemePermitted(identity, this.scheme))
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserIdToken(data);

                // Extract and check master token.
                var uitadMasterToken = uitad.masterToken;
                var uitadIdentity = uitadMasterToken.identity;
                if (!uitadIdentity)
                    throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED).setUserIdToken(uitad);
                if (identity != uitadIdentity)
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITY_MISMATCH, "entity identity " + identity + "; uad identity " + uitadIdentity).setUserIdToken(uitad);

                // Authenticate the user.
                var uitadUserIdToken = uitad.userIdToken;
                var user = uitadUserIdToken.user;
                if (!user)
                    throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED).setUserIdToken(uitad);

                // Verify the scheme is still permitted.
                if (!this._authutils.isSchemePermitted(identity, user, this.scheme))
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserIdToken(data);

                // Verify token has not been revoked.
                ctx.getTokenFactory().isUserIdTokenRevoked(ctx, uitadMasterToken, uitadUserIdToken, {
                    result: function(revokeMslError) {
                        AsyncExecutor(callback, function() {
                            if (revokeMslError)
                                throw new MslUserAuthException(revokeMslError, "User ID token used to authenticate was revoked.").setUserAuthenticationData(uitad);
                            validateIdentities(user, uitad);
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException)
                                throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR, "Error while checking User ID Token for revocation", e).setUserAuthenticationData(uitad);
                            throw e;
                        }, self);
                    }
                });
            }, self);
    
            function validateIdentities(user, uitad) {
                AsyncExecutor(callback, function() {
                    // If a user ID token was provided validate the user identities.
                    if (userIdToken) {
                        var uitUser = userIdToken.user;
                        if (!user.equals(uitUser))
                            throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser).setUserAuthenticationData(uitad);
                    }

                    // Return the user.
                    return user;
                }, self);
            }
            },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserIdTokenAuthenticationFactory'));
