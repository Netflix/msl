/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * <p>A queue that supports waiting for an element.</p>
 */
(function(require, module) {
	"use strict";
    
    var Class = require('../util/Class.js');
    var MslConstants = require('../MslConstants.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');

    /**
     * @param {number} number the ticket number.
     * @return the next larger ticket number, wrapped around.
     */
    function incrementTicket(number) {
        return (number == MslConstants.MAX_LONG_VALUE) ? 1 : number + 1;
    }

    /**
     * Return the provided queue's next waiter ticket number.
     *
     * @param {BlockingQueue} queue the blocking queue.
     * @return {number} the next waiter ticket number.
     */
    function nextWaiter(queue) {
        // If there are no more waiters then we're done.
        if (Object.keys(queue._waiters).length === 0) {
            return 0;
        }

        // Otherwise update the next waiter number.
        var next = incrementTicket(queue._nextWaiter);
        while (!queue._waiters[next])
            next = incrementTicket(next);
        return next;
    }

    var BlockingQueue = module.exports = Class.create({
        /**
         * Create a new blocking queue.
         */
        init: function init() {
            // The properties.
            var props = {
                /**
                 * Queue of elements.
                 * @type {Array.<*>}
                 */
                _queue: { value: [], writable: false, enumerable: false, configurable: false },
                /**
                 * Queue of readers waiting for an element.
                 * @type {Object.<number,Function>}
                 */
                _waiters: { value: {}, writable: false, enumerable: false, configurable: false },
                /**
                 * Next waiter number. [1,2^53] or 0 indicating no waiter.
                 * @type {number}
                 */
                _nextWaiter: { value: 0, writable: true, enumerable: false, configurable: false },
                /**
                 * Last added waiter number. [1,2^53] or 0 indicating no waiter.
                 * @type {number}
                 */
                _lastWaiter: { value: 0, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * Cancel the waiter identified by the given ticket.
         *
         * @param {number} ticket the ticket identifying the operation to
         *        cancel.
         */
        cancel: function cancel(ticket) {
            // Do nothing if the waiter is no longer waiting.
            if (!this._waiters[ticket]) return;

            // Grab the deliver function but do not execute it until after
            // updating the next waiter number in case deliver triggers a
            // callback to the queue.
            var deliver = this._waiters[ticket];
            delete this._waiters[ticket];
            if (ticket == this._nextWaiter)
                this._nextWaiter = nextWaiter(this);

            // Deliver undefined to the identified waiter.
            deliver.call(this, undefined);
        },

        /**
         * Cancel all waiters.
         */
        cancelAll: function cancelAll() {
            while (this._nextWaiter !== 0)
                this.cancel(this._nextWaiter);
        },

        /**
         * Retrieve and remove the head of the queue, waiting until an element
         * is available.
         *
         * @param {number} timeout timeout in milliseconds or -1 for no
         *        timeout.
         * @param {{result: function(?), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the next element from
         *        the queue or undefined if cancelled, be notified of timeout,
         *        or receive any thrown exceptions.
         * @return {number} a ticket with which the operation can be cancelled.
         */
        poll: function poll(timeout, callback) {
            var self = this;

            var number = incrementTicket(this._lastWaiter);
            this._lastWaiter = number;

            InterruptibleExecutor(callback, function() {
                // If there is something available then return it immediately.
                // This has to be done via a timeout to try and be fair to
                // waiters that have had their callbacks triggered.
                if (this._queue.length > 0) {
                    var elem = this._queue.shift();
                    // The actual delay will be clamped.
                    setTimeout(function() { callback.result(elem); }, 0);
                    return;
                }

                // Otherwise start the timeout and stick the waiter onto the
                // waiter queue. The timeout cannot execute before we return so
                // there is no chance of a race condition.
                var timeoutId;
                if (timeout != -1) {
                    timeoutId = setTimeout(function() {
                        // Trigger the timeout after we update the next waiter
                        // in case the timeout triggers a callback to the
                        // queue.
                        delete self._waiters[number];
                        if (number == self._nextWaiter)
                            self._nextWaiter = nextWaiter(self);
                        callback.timeout();
                    }, timeout);
                }
                this._waiters[number] = function(elem) {
                    clearTimeout(timeoutId);
                    // The actual delay will be clamped.
                    setTimeout(function() { callback.result(elem); }, 0);
                };
                if (!this._nextWaiter)
                    this._nextWaiter = number;
            }, self);

            // Return the cancellation ticket.
            return number;
        },

        /**
         * Add an element to the end of the queue.
         *
         * @param {*} elem the element.
         */
        add: function add(elem) {
            // If there is a waiter deliver the element directly.
            if (this._nextWaiter) {
                // Grab the deliver function but do not execute it until after
                // updating the next waiter number in case delivery triggers
                // a callback to the queue.
                var deliver = this._waiters[this._nextWaiter];
                delete this._waiters[this._nextWaiter];
                this._nextWaiter = nextWaiter(this);

                // Deliver the element.
                deliver.call(this, elem);
                return;
            }

            // Otherwise stick the element on the queue.
            this._queue.push(elem);
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('BlockingQueue'));
