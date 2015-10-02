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
 * <p>A {@code MslTokenizer} takes in a binary source and parses out
 * {@link MslObject} and {@link MslArray} instances.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MslTokenizer;

(function() {
    "use strict";

    MslTokenizer = util.Class.create({
        /**
         * <p>Create a new tokenizer.</p>
         */
        init: function init() {
            // The properties.
            var props = {
                /**
                 * Cached next object.
                 * @type {?MslObject}
                 */
                next: { value: null, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * <p>Returns true if more objects can be read from the data source. This
         * method determines that by actually trying to read the next object.</p>
         * 
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive true if more objects
         *        are available from the data source or any thrown exceptions.
         * @throws MslEncoderException if the next object cannot be read or the
         *         source data at the current position is invalid.
         */
        more: function more(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                if (this.next) return true;
                nextObject(timeout, {
                    result: function(o) {
                        InterruptibleExecutor(callback, function() {
                            this.next = o;
                            return (this.next);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
        },
        
        /**
         * <p>Return the next object (should be an instance of {@link MslObject} or
         * {@link MslArray}) from the source data.</p>
         * 
         * <p>If the source data's current position cannot be parsed as an object,
         * an exception is thrown and the source data position's new position is
         * undefined. Subsequent calls to this function should not re-throw the
         * exception and instead should look for the next object. The algorithm
         * used to search for the next object, and how the position should be set
         * to do so, is up to the implementer and may depend upon the encoding.</p>
         * 
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MslObject), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the next object or
         *        {@code null} if there are no more, or any thrown exceptions.
         * @throws MslEncoderException if the next object cannot be read or the
         *         source data at the current position is invalid.
         */
        next: function(timeout, callback) {
            callback.error(new MslInternalException("MslTokenizer.next() must be implemented by a subclass."));
        },
        
        /**
         * <p>Return the next object.</p>
         * 
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MslObject), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the next object or
         *        {@code null} if there are no more, or any thrown exceptions.
         * @throws MslEncoderException if the next object cannot be read or the
         *         source data at the current position is invalid.
         */
        nextObject: function nextObject(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                if (this.next != null) {
                    var mo = next;
                    this.next = null;
                    return mo;
                }
                next(timeout, callback);
            }, self);
        },
    });
})();
