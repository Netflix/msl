/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
 * <p>The message capabilities identify the features supported by the message
 * sender.</p>
 * 
 * <p>The message capabilities are represented as
 * {@code
 * capabilities = {
 *   "compressionalgos" : [ enum(GZIP|LZW) ],
 *   "languages" : [ "string" ],
 * }} where:
 * <ul>
 * <li>{@code compressionalgos} is the set of supported compression algorithms</li>
 * <li>{@code languages} is the preferred list of BCP-47 languages in descending order</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MessageCapabilities;
var MessageCapabilities$parse;
var MessageCapabilities$intersection;

(function() {
    /**
     * JSON key compression algorithms.
     * @const
     * @type {string}
     */
    var KEY_COMPRESSION_ALGOS = "compressionalgos";
    /**
     * JSON key languages.
     * @const
     * @type {string}
     */
    var KEY_LANGUAGES = "languages";
    
    /**
     * Computes and returns the intersection of two arrays.
     */
    function computeIntersection(a, b) {
        var hash = {},
            intersection = [],
            i;
        for (i = 0; i < a.length; ++i) {
            hash[a[i]] = true;
        }
        for (i = 0; i < b.length; ++i) {
            if (hash[b[i]])
                intersection.push(b[i]);
        }
        return intersection;
    }
    
    /**
     * Computes and returns the intersection of two message capabilities.
     * 
     * @param {?MessageCapabilities} mc1 first message capabilities. May be {@code null}.
     * @param {?MessageCapabilities} mc2 second message capabilities. May be {@code null}.
     * @return {?MessageCapabilities} the intersection of message capabilities or {@code null} if one
     *         of the message capabilities is {@code null}.
     */
    MessageCapabilities$intersection = function MessageCapabilities$intersection(mc1, mc2) {
        if (!mc1 || !mc2)
            return null;
        
        // Compute the intersection of compression algorithms.
        var compressionAlgos = computeIntersection(mc1.compressionAlgorithms, mc2.compressionAlgorithms);
        
        // Compute the intersection of languages. This may not respect order.
        var languages = computeIntersection(mc1.languages, mc2.languages);
        
        return new MessageCapabilities(compressionAlgos, languages);
    };

    MessageCapabilities = util.Class.create({
        /**
         * Create a new message capabilities object with the specified supported
         * features.
         *
         * @param {Array.<MslConstants$CompressionAlgorithm>} compressionAlgos supported payload compression algorithms.
         * @param {Array.<String>} languages preferred languages as BCP-47 codes in descending
         *        order. May be {@code null}.
         */
        init: function init(compressionAlgos, languages) {
            if (!compressionAlgos)
                compressionAlgos = [];
            if (!languages)
                languages = [];
            compressionAlgos.sort();

            // The properties.
            var props = {
                /** @type {Array.<MslConstants$CompressionAlgorithm>} */
                compressionAlgorithms: { value: compressionAlgos, writable: false, enumerable: true, configurable: false },
                /** @type {Array.<String>} */
                languages: { value: languages, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var result = {};
            result[KEY_COMPRESSION_ALGOS] = this.compressionAlgorithms;
            result[KEY_LANGUAGES] = this.languages;
            return result;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof MessageCapabilities)) return false;
            return Arrays$containEachOther(this.compressionAlgorithms, that.compressionAlgorithms) &&
                   Arrays$containEachOther(this.languages, that.languages);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return this.compressionAlgorithms.join(':') + '|' + this.languages.join(':');
        },
    });

    /**
     * Construct a new message capabilities object from the provided JSON
     * object.
     *
     * @param {Object} capabilitiesJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    MessageCapabilities$parse = function MessageCapabilities$parse(capabilitiesJO) {
        // Pull the capabilities.
        var algos = capabilitiesJO[KEY_COMPRESSION_ALGOS];
        var langs = capabilitiesJO[KEY_LANGUAGES];

        // Verify compression algorithms.
        if ((algos && !(algos instanceof Array)) ||
            (langs && !(langs instanceof Array)))
        {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "capabilities " + JSON.stringify(capabilitiesJO));
        }

        // Extract compression algorithms.
        var compressionAlgos = [];
        for (var i = 0; algos && i < algos.length; ++i) {
            var algo = algos[i];
            // Ignore unsupported algorithms.
            if (MslConstants$CompressionAlgorithm[algo])
                compressionAlgos.push(algo);
        }

        // Return the capabilities.
        return new MessageCapabilities(compressionAlgos, langs);
    };
})();
