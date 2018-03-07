/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
 * <p>Default {@link MslEncoderFactory} implementation that supports the
 * following encoder formats:
 * <ul>
 * <li>JSON: backed by the Clarinet parser.</li>
 * </ul>
 * </p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslEncoderFactory = require('../io/MslEncoderFactory.js');
    var MslEncoderFormat = require('../io/MslEncoderFormat.js');
    var JsonMslTokenizer = require('../io/JsonMslTokenizer.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var JsonMslObject = require('../io/JsonMslObject.js');
    
	var DefaultMslEncoderFactory = module.exports = MslEncoderFactory.extend({
	    /** @inheritDoc */
        getPreferredFormat: function getPreferredFormat(formats) {
            // We don't know about any other formats right now.
            return MslEncoderFormat.JSON;
        },
	    
	    /** @inheritDoc */
        generateTokenizer: function generateTokenizer(source, format) {
            // JSON.
            if (MslEncoderFormat.JSON === format)
                return new JsonMslTokenizer(this, source);
            
            // Unsupported encoding format.
            throw new MslEncoderException("Unsupported encoder format: " + format + ".");
        },
	    
	    /** @inheritDoc */
        parseObject: function parseObject(encoding) {
            // Identify the encoder format.
            var format = this.parseFormat(encoding);
            
            // JSON.
            if (MslEncoderFormat.JSON == format)
                return new JsonMslObject(this, encoding);
            
            // Unsupported encoder format.
            throw new MslEncoderException("Unsupported encoder format: " + format + ".");
        },

	    /** @inheritDoc */
        encodeObject: function encodeObject(object, format, callback) {
            AsyncExecutor(callback, function() {
                // JSON.
                if (MslEncoderFormat.JSON == format) {
                    JsonMslObject.encode(this, object, callback);
                    return;
                }

                // Unsupported encoder format.
                throw new MslEncoderException("Unsupported encoder format: " + format + ".");
            }, this);
        },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('DefaultMslEncoderFactory'));
