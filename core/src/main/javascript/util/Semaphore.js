/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
 * <p>A semaphore.</p>
 */
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    var MslConstants = require('../MslConstants.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
    var MslInternalException = require('../MslInternalException.js');

    /**
     * @param {number} the ticket number.
     * @return the next larger ticket number, wrapped around.
     */
    function incrementTicket(number) {
        return (number == MslConstants.MAX_LONG_VALUE) ? 1 : number + 1;
    }

    /**
     * Return the provided semaphore's next waiter ticket number.
     *
     * @param {Semaphore} sem the sempahore.
     * @return {number} the next waiter ticket number.
     */
    function nextWaiter(sem) {
        // If there are no more waiters then we're done.
        if (Object.keys(sem._waiters).length === 0) {
            return 0;
        }

        // Otherwise update the next waiter number.
        var next = incrementTicket(sem._nextWaiter);
        while (!sem._waiters[next])
            next = incrementTicket(next);
        return next;
    }
    
    var Semaphore = module.exports = Class.create({
        /**
         * Create a new sempahore.
         * 
         * @param {number} count the initial number of available resources.
         */
        init: function init(count) {
            // The properties.
            var props = {
                /**
                 * Current number of available resources.
                 * @type {number}
                 */
                _available: { value: count, writable: true, enumerable: false, configurable: false },
                /**
                 * Maximum number of available resources.
                 * @type {number}
                 */
                _maximum: { value: count, writable: false, enumerable: false, configurable: false },
                /**
                 * Queue of readers waiting for a resource.
                 * @type {Object.<number,function()}
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
         * Cancel a waiter identified by the given ticket.
         * 
         * @param {number} ticket the ticket identifying the operation to
         *        cancel.
         */
        cancel: function cancel(ticket) {
            // Do nothing if the waiter is no longer waiting.
            if (!this._waiters[ticket]) return;

            // Deliver false to the identified waiter.
            this._waiters[ticket].call(this, false);
            delete this._waiters[ticket];

            // If this is the next waiter then update the next waiter number.
            if (ticket == this._nextWaiter)
                this._nextWaiter = nextWaiter(this);
        },

        /**
         * Cancel all waiters.
         */
        cancelAll: function cancelAll() {
            while (this._nextWaiter !== 0)
                this.cancel(this._nextWaiter);
        },

        /**
         * Wait until a resource is available.
         *
         * @param {number} timeout timeout in milliseconds or -1 for no
         *        timeout.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive true if the resource
         *        has been acquired or false if cancelled, be notified of
         *        timeout, or receive any thrown exceptions.
         * @return {number} a ticket with which the operation can be cancelled
         *         or 0 if the resource was immediately acquired.
         */
        wait: function wait(timeout, callback) {
            var self = this;
            
            // If a resource is available, allow immediate acquisition.
            if (this._available > 0) {
                --this._available;
                // The actual delay will be clamped.
                setTimeout(function() { callback.result(true); }, 0);
                return 0;
            }
            
            // Otherwise wait until a resource is available.
            var number = incrementTicket(this._lastWaiter);
            this._lastWaiter = number;

            InterruptibleExecutor(callback, function() {
                // Start the timeout and stick the waiter onto the waiter queue.
                // The timeout cannot execute before we return so there is no
                // chance of a race condition.
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
                    
                    // If not being cancelled, acquire one of the resources.
                    if (elem) {
                        // Make sure a resource is available.
                        if (this._available <= 0) {
                            // The actual delay will be clamped.
                            setTimeout(function() { callback.error(new MslInternalException("Semaphore waiter signaled without any available resources.")); }, 0);
                            return;
                        }
                        
                        --this._available;
                    }
                    
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
         * Release a resource.
         */
        signal: function signal(ticket) {
            // Make sure signal hasn't been called too many times.
            if (this._available == this._maximum)
                throw new MslInternalException("Sempahore signaled despite all resources being already available.");
            
            // Increment the number of available resources.
            ++this._available;
            
            // If there is a waiter signal it.
            if (this._nextWaiter) {
                // Grab the signaling function but do not execute it until
                // after updating the next waiter number in case signaling
                // triggers a callback to the queue.
                var signaling = this._waiters[this._nextWaiter];
                delete this._waiters[this._nextWaiter];
                this._nextWaiter = nextWaiter(this);
                
                // Signal the waiter.
                signaling.call(this, true);
                return;
            }
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('Semaphore'));
