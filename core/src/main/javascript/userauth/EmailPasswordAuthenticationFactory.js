/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * Email/password-based user authentication factory.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var UserAuthenticationFactory = require('../userauth/UserAuthenticationFactory.js');
    var UserAuthenticationScheme = require('../userauth/UserAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var EmailPasswordAuthenticationData = require('../userauth/EmailPasswordAuthenticationData.js');
    var MslInternalException = require('../MslInternalException.js');
    var MslUserAuthException = require('../MslUserAuthException.js');
    var MslError = require('../MslError.js');
    
    var EmailPasswordAuthenticationFactory = module.exports = UserAuthenticationFactory.extend({
        /**
         * Construct a new email/password-based user authentication factory.
         *
         * @param {EmailPasswordStore} store email/password store.
         * @param {AuthenticationUtils} authutils authentication utilities.
         */
        init: function init(store, authutils) {
            init.base.call(this, UserAuthenticationScheme.EMAIL_PASSWORD);
    
            // The properties.
            var props = {
                _store: { value: store, writable: false, enumerable: false, configurable: false },
                _authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /** @inheritDoc */
        createData: function createData(ctx, masterToken, userAuthMo, callback) {
            AsyncExecutor(callback, function() {
                return EmailPasswordAuthenticationData.parse(userAuthMo);
            }, this);
        },
    
        /** @inheritDoc */
        authenticate: function authenticate(ctx, identity, data, userIdToken, callback) {
            AsyncExecutor(callback, function() {
                // Make sure we have the right kind of user authentication data.
                if (!(data instanceof EmailPasswordAuthenticationData))
                    throw new MslInternalException("Incorrect authentication data type " + data + ".");
                var epad = data;

                // Verify the scheme is permitted.
                if(!this._authutils.isSchemePermitted(identity, this.scheme))
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

                // Extract and check email and password values.
                var email = epad.email;
                var password = epad.password;
                if (!email || email.trim().length == 0 ||
                        !password || password.trim().length == 0)
                {
                    throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad); 
                }

                // Authenticate the user.
                var user = this._store.isUser(email, password);
                if (user == null)
                    throw new MslUserAuthException(MslError.EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);

                // Verify the scheme is still permitted.
                if (!this._authutils.isSchemePermitted(identity, user, this.scheme))
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.scheme + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

                // If a user ID token was provided validate the user identities.
                if (userIdToken) {
                    var uitUser = userIdToken.user;
                    if (!user.equals(uitUser))
                        throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser).setUserAuthenticationData(epad);
                }

                // Return the user.
                return user;
            }, this);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('EmailPasswordAuthenticationFactory'));
