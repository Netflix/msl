/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
var SimpleProfileRequest;

(function() {
    "use strict";
    
    // Shortcuts.
    var Type = SimpleRequest$Type;
    
    /**
     * <p>Request to return a user profile.</p>
     * 
     * <p>The request data object is defined as an empty JSON object.</p>
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    SimpleProfileRequest = SimpleRequest.extend({
        /**
         * <p>Create a new user profile request.</p>
         */
        init: function init() {
            init.base.call(this, Type.USER_PROFILE);
        },
    
        /** @inheritDoc */
        getData: function getData() {
            return {};
        },
    });
})();