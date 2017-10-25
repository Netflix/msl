/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>MSL encoder formats.</p>
 * 
 * <p>The format name is used to uniquely identify encoder formats.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
    
    /**
     * Map of names onto formats.
     * @type {Object<string,MslEncodingFormat>}
     */
    var formatsByName = {};
    /**
     * Map of identifiers onto formats.
     * @type {Object<number,MslEncodingFormat>}
     */
    var formatsById = {};
    
    /**
     * JSON identifier.
     * @type {number}
     * @const
     */
    var JSON_IDENTIFIER = 0x7b; // '{'

    /**
     * Define an encoding format with the specified name and byte stream
     * identifier.
     * 
     * @param {string} name the encoder format name.
     * @param {number} identifier the byte stream identifier.
     */
    var MslEncoderFormat = module.exports = function MslEncoderFormat(name, identifier) {
        // The properties.
        var props = {
            name: { value: name, writable: false, configurable: false },
            identifier: { value: identifier, writable: false, configurable: false },
        };
        Object.defineProperties(this, props);
        
        // Add this format to the maps.
        formatsByName[name] = this;
        formatsById[identifier] = this;
    };
    
    Class.mixin(MslEncoderFormat,
    /** @lends {MslEncoderFormat} */
    ({
        /** JSON. */
        JSON : new MslEncoderFormat("JSON", JSON_IDENTIFIER),
        
        /**
         * @param {string|number} f the encoding format name or identifier.
         * @return {MslEncoderFormat} the encoding format identified by the specified name or
         *         identifier, or {@code null} if there is none.
         */
        getFormat: function getFormat(f) {
            if (typeof f === 'string' && formatsByName[f])
                return formatsByName[f];
            if (formatsById[f])
                return formatsById[f];
            return null;
        },
    }));
    Object.freeze(MslEncoderFormat);
    
    // Exports.
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslEncoderFormat'));