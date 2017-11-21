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
 * Test MSL user.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslUser = require('msl-core/tokens/MslUser.js');
        
    var MockMslUser = module.exports = MslUser.extend({
        /**
         * Create a new MSL user with the specified user ID.
         * 
         * @param {string} id MSL user ID.
         */
        init: function init(id) {
            // Set properties.
            var props = {
                id: { value: id, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        getEncoded: function getEncoded() {
            return this.id;
        },
    
        /** @inheritDoc */
        equals: function equals(obj) {
            if (obj === this) return true;
            if (!(obj instanceof MockMslUser)) return false;
            var that = obj;
            return this.id == that.id;
        },
    
        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return this.id;
        },
    });
    
    /**
     * Create a new MSL user from the serialized user data.
     * 
     * @param {Uint8Array} userdata serialized user data.
     * @return {MslUser} the MSL user.
     */
    function MockMslUser$parse(userdata) {
        return new MockMslUser(userdata);
    }
    
    // Exports.
    module.exports.parse = MockMslUser$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockMslUser'));