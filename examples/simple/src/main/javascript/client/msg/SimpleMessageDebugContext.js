/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

(function(require, module) {
    "use strict";

    var MessageDebugContext = require('msl-core/msg/MessageDebugContext.js');

    var SimpleMessageDebugContext = module.exports = MessageDebugContext.extend({
        /**
         * <p>Create a new message debug context that is tied to the provided
         * HTML text elements.</p>
         *
         * @param {Element} sentText sent text HTML DOM element.
         * @param {Element} receivedText received text HTML DOM element.
         */
        init: function init(sentText, receivedText) {
            // Set properties.
            var props = {
                _sent: { value: sentText, writable: false, enumerable: false, configurable: false },
                _received: { value: receivedText, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        sentHeader: function sentHeader(header) {
            // Append a pair of newlines. This should terminate the message
            // data logged by the filter output stream.
            this._sent.innerHTML += "\n\n";
        },

        /** @inheritDoc */
        receivedHeader: function receivedHeader(header) {
            // Append a pair of newlines. This should terminate the message
            // data logged by the filter input stream.
            this._received.innerHTML += "\n\n";
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleMessageDebugContext'));
