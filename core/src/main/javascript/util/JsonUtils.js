/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
var JsonUtils$merge;

(function() {
    "use strict";
    
    /**
     * Merge two JSON objects into a single JSON object. If the same key is
     * found in both objects, the second object's value is used. The values are
     * copied by reference so this is a shallow copy.
     * 
     * @param {?Object} jo1 first JSON object. May be null.
     * @param {?Object} jo2 second JSON object. May be null.
     * @return {?Object} the merged JSON object or null if both arguments are null.
     */
    JsonUtils$merge = function JsonUtils$merge(jo1, jo2) {
        // Return null if both objects are null.
        if (!jo1 && !jo2)
            return null;
        
        // Create the final object.
        var jo = {};

        // Copy the contents of the first object into the final object.
        if (jo1) {
            for (var key in jo1)
                jo[key] = jo1[key];
        }
        
        // Copy the contents of the second object into the final object.
        if (jo2) {
            for (var key in jo2)
                jo[key] = jo2[key];
        }
        
        // Return the final object.
        return jo;
    };
})();