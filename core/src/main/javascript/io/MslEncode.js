/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
var MslEncode;

(function() {
    "use strict";

    /**
     * @interface
     */
    MslEncode = util.Class.create({
        /**
         * Returns a MSL encoding of the implementing class.
         * 
         * @param {MslEncodingFormat} format the encoding format.
         * @return {Uint8Array} a MSL encoding.
         * @throws MslEncoderException if the encoding format is not supported.
         */
        toMslEncode: function(final MslEncodingFormat format) {},
    });
})();
