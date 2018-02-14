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
 * Test email/password authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var UserAuthenticationFactory = require('msl-core/userauth/UserAuthenticationFactory.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var EmailPasswordAuthenticationData = require('msl-core/userauth/EmailPasswordAuthenticationData.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');
    var MslError = require('msl-core/MslError.js');
    
    var MockMslUser = require('../tokens/MockMslUser.js');
    
    /** Email. */
    var EMAIL = "email1@domain.com";
    /** Password. */
    var PASSWORD = "password";
    /** User. (312204600) */
    var USER = new MockMslUser("22e1c7a53da436cfe4096860861592e7");
    
    /** Email #2. */
    var EMAIL_2 = "email2@domain.com";
    /** Password #2. */
    var PASSWORD_2 = "password2";
    /** User #2. (880083944) */
    var USER_2 = new MockMslUser("8422c679242f709891ef4699301abdb2");

    var MockEmailPasswordAuthenticationFactory = module.exports = UserAuthenticationFactory.extend({
        /**
         * Create a new test email/password authentication factory.
         */
        init: function init() {
            init.base.call(this);
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
                
                // Extract and check email and password values.
                var email = data.email;
                var password = data.password;
                if (!email || email.trim().length == 0 ||
                    !password || password.trim().length == 0)
                {
                    throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
                }
                
                // Identify the user.
                var user;
                if (EMAIL == email && PASSWORD == password)
                    user = USER;
                else if (EMAIL_2 == email && PASSWORD_2 == password)
                    user = USER_2;
                else
                    throw new MslUserAuthException(MslError.EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);
                
                // If a user ID token was provided validate the user identities.
                if (userIdToken) {
                    var uitUser = userIdToken.user;
                    if (!user.equals(uitUser))
                        throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser);
                }
                
                // Return the user.
                return user;
            }, this);
        },
    });
    
    // Expose public static properties.
    module.exports.EMAIL = EMAIL;
    module.exports.PASSWORD = PASSWORD;
    module.exports.USER = USER;
    module.exports.EMAIL_2 = EMAIL_2;
    module.exports.PASSWORD_2 = PASSWORD_2;
    module.exports.USER_2 = USER_2;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockEmailPasswordAuthenticationFactory'));