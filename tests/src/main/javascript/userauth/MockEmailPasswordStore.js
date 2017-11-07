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
 * Test email/password store.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EmailPasswordStore = require('msl-core/userauth/EmailPasswordStore.js');
    
    /**
     * Create a new user and password pair.
     * 
     * @param {MslUser} user MSL user.
     * @param {string} password user password.
     */
    function UserAndPassword(user, password) {
        this.user = user;
        this.password = password;
    }
    
    var MockEmailPasswordStore = module.exports = EmailPasswordStore.extend({
        init: function init() {
            // Map of email addresses onto user ID and password pairs.
            var credentials = {};
            
            // The properties.
            var props = {
                _credentials: { value: credentials, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * Add a user to the store.
         * 
         * @param {string} email email address.
         * @param {string} password password.
         * @param {MslUser} user user.
         */
        addUser: function addUser(email, password, user) {
            if (email.trim().length == 0)
                throw new TypeError("Email cannot be blank.");
            if (password.trim().length == 0)
                throw new TypeError("Password cannot be blank.");

            var iap = new UserAndPassword(user, password);
            this._credentials[email] = iap;
        },

        /**
         * Clear all known users.
         */
        clear: function clear() {
            this._credentials = {};
        },

        /** @inheritDoc */
        isUser: function isUser(email, password) {
            var iap = this._credentials[email];
            if (!iap || iap.password != password)
                return null;
            return iap.user;
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockEmailPasswordStore'));
