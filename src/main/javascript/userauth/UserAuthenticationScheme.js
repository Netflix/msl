/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
 * <p>User authentication schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify user authentication
 * schemes.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var UserAuthenticationScheme;
var UserAuthenticationScheme$getScheme;

(function() {
    "use strict";
    
    /** Map of names onto schemes. */
    var schemes = {};
    
    /**
     * Define a user authentication scheme with the specified name.
     * 
     * @param {string} name the user authentication scheme name.
     */
    UserAuthenticationScheme = function UserAuthenticationScheme(name) {
        // The properties.
        var props = {
            name: { value: name, writable: false, configurable: false },
        };
        Object.defineProperties(this, props);
        
        // Add this scheme to the map.
        schemes[name] = this;
    };
    
    util.Class.mixin(UserAuthenticationScheme,
    /** @lends UserAuthenticationScheme */
    ({
        /** Email/password. */
        EMAIL_PASSWORD : new UserAuthenticationScheme("EMAIL_PASSWORD"),
        USER_ID_TOKEN : new UserAuthenticationScheme("USER_ID_TOKEN"),
    }));
    Object.freeze(UserAuthenticationScheme);

    /**
     * @param {string} name the entity authentication scheme name.
     * @return {?UserAuthenticationScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    UserAuthenticationScheme$getScheme = function UserAuthenticationScheme$getScheme(name) {
        return (schemes[name]) ? schemes[name] : null;
    };
})();