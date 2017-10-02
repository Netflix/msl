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
 * <p>This interface allows a class to override the default behavior when being
 * encoded into a {@link MslObject} or {@link MslArray}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
    
    var Class = require('../util/Class.js');

    /**
     * @interface
     */
    var MslEncodable = module.exports = Class.create({
        /**
         * Returns the requested encoding of a MSL object representing the
         * implementing class.
         * 
         * @param {MslEncoderFactory} encoder the encoder factory.
         * @param {MslEncoderFormat} format the encoder format.
         * @param {{result: function(Uint8Array), error: function(Error)}}
         *        callback the callback that will receive the MSL encoding of
         *        the MSL object or any thrown exceptions.
         * @throws MslEncoderException if the encoder format is not supported or
         *         there is an error encoding the data.
         */
        toMslEncoding: function(encoder, format, callback) {},
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslEncodable'));
