/**
 * Copyright (c) 2013-2015 Netflix, Inc.  All rights reserved.
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
 * Thrown when there is a problem with a user ID token, but the token was
 * successfully parsed.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MslUserIdTokenException = MslException.extend({
    /**
     * Construct a new MSL user ID token exception with the specified error and
     * user ID token.
     *
     * @param {MslError} error the error.
     * @param {UserIdToken} userIdToken the user ID token. May be null or undefined.
     * @param {string} details the details text. May be null or undefined.
     */
    init: function init(error, userIdToken, details) {
        init.base.call(this, error, details);

        // The properties.
        var props = {
            userIdToken: { value: userIdToken, writable: false, configurable: false },
            name: { value: "MslUserIdTokenException", writable: false, configurable: true }
        };
        Object.defineProperties(this, props);
    },
});
