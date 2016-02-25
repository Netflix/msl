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
var MslEncoderUtils$merge;

(function() {
    "use strict";
    
    /**
     * Merge two MSL objects into a single MSL object. If the same key is
     * found in both objects, the second object's value is used. The values are
     * copied by reference so this is a shallow copy.
     * 
     * @param {?MslObject} mo1 first MSL object. May be null.
     * @param {?MslObject} mo2 second MSL object. May be null.
     * @return {?MslObject} the merged MSL object or null if both arguments are null.
     * @throws MslEncoderException if a value in one of the arguments is
     *         invalid—this should not happen.
     */
    MslEncoderUtils$merge = function MslEncoderUtils$merge(mo1, mo2) {
        // Return null if both objects are null.
        if (!mo1 && !mo2)
            return null;

        // Make a copy of the first object, or create an empty object.
        var mo = (mo1)
            ? new MslObject(mo1.getMap())
            : {};

        // If the second object is null, we're done and just return the copy.
        if (!mo2)
            return mo;
        
        // Copy the contents of the second object into the final object.
        for (var key in mo2.getKeys())
            mo.put(key, mo2.get(key));
        return mo;
    };
})();