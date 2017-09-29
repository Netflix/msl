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
 * <p>A read-write lock allows multiple readers to simultaneously acquire the
 * lock and a single writer to exclusively acquire the lock. A writer will
 * block until there are no readers and then acquire the lock. Readers will
 * block if there is a writer waiting to acquire the lock.</p>
 *
 * <p>This lock is not reentrant, so while a reader can recursively acquire the
 * lock multiple times a writer cannot. A reader also cannot acquire the write
 * lock recursively.</p>
 */
(function(require, module) {
	"use strict";
	
	var MslConstants = require('../MslConstants.js');
	var Class = require('../util/Class.js');
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
     * Return the provided read-write lock's next waiting reader's ticket
     * number.
     * 
     * @param {ReadWriteLock} rwlock the read-write lock.
     * @return {number} the next waiting reader's ticket number.
     */
    function nextReader(rwlock) {
        // If there are no more readers then we're done.
        if (Object.keys(rwlock._waitingReaders).length === 0) {
            return 0;
        }

        // Otherwise update the next reader number.
        var next = incrementTicket(rwlock._nextReader);
        while (!rwlock._waitingReaders[next])
            next = incrementTicket(next);
        return next;
    }
    
    /**
     * Return the provided read-write lock's next waiting writer's ticket
     * number.
     * 
     * @param {ReadWriteLock} rwlock the read-write lock.
     * @return {number} the next waiting writer's ticket number.
     */
    function nextWriter(rwlock) {
        // If there are no more writers then we're done.
        if (Object.keys(rwlock._waitingWriters).length === 0) {
            return 0;
        }

        // Otherwise update the next writer number.
        var next = incrementTicket(rwlock._nextWriter);
        while (!rwlock._waitingWriters[next])
            next = incrementTicket(next);
        return next;
    }

    var ReadWriteLock = module.exports = Class.create({
        /**
         * Create a new read-write lock.
         */
        init: function init() {
            // The properties.
            var props = {
                /**
                 * List of readers who have acquired the lock.
                 * @type {Object.<number,boolean>}
                 */
                _readers: { value: {}, writable: false, enumerable: false, configurable: false },
                /**
                 * Queue of readers waiting to acquire the lock.
                 * @type {Object.<number,Function>}
                 */
                _waitingReaders: { value: {}, writable: false, enumerable: false, configurable: false },
                /**
                 * Writer who has acquired the lock.
                 * @type {number}
                 */
                _writer: { value: null, writable: true, enumerable: false, configurable: false },
                /**
                 * Queue of writers waiting to acquire the lock.
                 * @type {Object.<number,Function>}
                 */
                _waitingWriters: { value: {}, writable: false, enumerable: false, configurable: false },
                /**
                 * Next waiting reader number. [1,2^53] or 0 indicating no next reader.
                 * @type {number}
                 */
                _nextReader: { value: 0, writable: true, enumerable: false, configurable: false },
                /**
                 * Next waiting writer number. [1,2^53] or 0 indicating no next writer.
                 * @type {number}
                 */
                _nextWriter: { value: 0, writable: true, enumerable: false, configurable: false },
                /**
                 * Last added reader/writer number. [1,2^53] or 0 indicating no
                 * reader or writer.
                 * @type {number}
                 */
                _lastNumber: { value: 0, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * Cancel the waiter identifed by the given ticket.
         *
         * @param {number} ticket the ticket identifying the operation to
         *        cancel.
         */
        cancel: function cancel(ticket) {
            // Deliver undefined to a waiting reader after updating the next
            // reader number in case deliver triggers a callback to the read-
            // write lock.
            if (this._waitingReaders[ticket]) {
                var deliverR = this._waitingReaders[ticket];
                delete this._waitingReaders[ticket];
                if (ticket == this._nextReader)
                    this._nextReader = nextReader(this);
                deliverR.call(this, true);
            }

            // Deliver undefined to a waiting writer after updating the next
            // writer number in case deliver triggers a callback to the read-
            // write lock.
            if (this._waitingWriters[ticket]) {
                var deliverW = this._waitingWriters[ticket];
                delete this._waitingWriters[ticket];
                if (ticket == this._nextWriter)
                    this._nextWriter = nextWriter(this);
                deliverW.call(this, true);
            }
        },

        /**
         * Cancel all waiting readers and writers.
         */
        cancelAll: function cancelAll() {
            while (this._nextWriter !== 0)
                this.cancel(this._nextWriter);
            while (this._nextReader !== 0)
                this.cancel(this._nextReader);
        },

        /**
         * Acquire the read lock. A ticket number will be returned which must
         * be used to release the lock.
         *
         * @param {number} timeout lock acquisition timeout in milliseconds or
         *        -1 for no timeout.
         * @param {{result: function(number), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the lock ticket
         *        number or undefined if cancelled, timeout, or any thrown
         *        exceptions.
         * @return {number} a ticket with which the operation can be cancelled.
         */
        readLock: function readLock(timeout, callback) {
            var self = this;

            var number = incrementTicket(this._lastNumber);
            this._lastNumber = number;

            InterruptibleExecutor(callback, function() {
                // If there is no writer grab the lock immediately.
                if (!this._writer && Object.keys(this._waitingWriters).length === 0) {
                    this._readers[number] = true;
                    return number;
                }

                // Otherwise, start the timeout and stick the reader onto the
                // reader queue. The timeout cannot execute before we return so
                // there is no chance of a race condition.
                var timeoutId;
                if (timeout != -1) {
                    timeoutId = setTimeout(function() {
                        // Trigger the timeout after we update the next reader
                        // in case the timeout triggers a callback to the read-
                        // write lock.
                        delete self._waitingReaders[number];
                        if (number == self._nextReader)
                            self._nextReader = nextReader(self);
                        callback.timeout();
                    }, timeout);
                }
                this._waitingReaders[number] = function(cancelled) {
                    clearTimeout(timeoutId);
                    // The actual delay will be clamped.
                    if (!cancelled) {
                        self._readers[number] = true;
                        setTimeout(function() { callback.result(number); }, 0);
                    } else {
                        setTimeout(function() { callback.result(undefined); }, 0);
                    }
                };
                if (!this._nextReader)
                    this._nextReader = number;
            }, self);

            // Return the cancellation ticket.
            return number;
        },

        /**
         * Acquire the write lock. A ticket number will be returned which must
         * be used to release the lock.
         *
         * @param {number} timeout lock acquisition timeout in milliseconds or
         *        -1 for no timeout.
         * @param {{result: function(number), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the lock ticket
         *        number or undefined if cancelled, timeout, or any thrown
         *        exceptions.
         * @return {number} a ticket with which the operation can be cancelled.
         */
        writeLock: function writeLock(timeout, callback) {
            var self = this;

            var number = incrementTicket(this._lastNumber);
            this._lastNumber = number;

            InterruptibleExecutor(callback, function() {
                // If there are no readers or writer then grab the lock
                // immediately.
                if (Object.keys(this._readers).length === 0 &&
                    Object.keys(this._waitingReaders).length === 0 &&
                    !this._writer)
                {
                    this._writer = number;
                    return number;
                }

                // Otherwise, start the timeout and stick the writer onto the
                // writer queue. The timeout cannot execute before we return so
                // there is no chance of a race condition.
                var timeoutId;
                if (timeout != -1) {
                    timeoutId = setTimeout(function() {
                        // Trigger the timeout after we update the next writer
                        // in case the timeout triggers a callback to the read-
                        // write lock.
                        delete self._waitingWriters[number];
                        if (number == self._nextWriter)
                            self._nextWriter = nextWriter(self);
                        callback.timeout();
                    }, timeout);
                }
                this._waitingWriters[number] = function(cancelled) {
                    clearTimeout(timeoutId);
                    // The actual delay will be clamped.
                    if (!cancelled) {
                        self._writer = number;
                        setTimeout(function() { callback.result(number); }, 0);
                    } else {
                        setTimeout(function() { callback.result(undefined); }, 0);
                    }
                };
                if (!this._nextWriter)
                    this._nextWriter = number;
            }, self);

            // Return the cancellation ticket.
            return number;
        },

        /**
         * Release the read or write lock using the ticket number received when
         * the lock was acquired.
         *
         * @param {number} number the ticket number.
         */
        unlock: function unlock(number) {
            // Remove the reader or writer from the active set.
            if (number == this._writer) {
                this._writer = null;
            } else {
                if (!this._readers[number])
                    throw new MslInternalException("There is no reader or writer with ticket number " + number + ".");
                delete this._readers[number];
            }

            // If there is a waiting writer...
            if (this._nextWriter) {
                // If there are active readers then don't activate anyone. The
                // waiting writer will be activated once the last active reader
                // releases the lock.
                if (Object.keys(this._readers).length > 0)
                    return;
                
                // Grab the activation function but do not execute it until
                // after updating the next writer number in case activating
                // triggers a callback to the read-write lock.
                var activateW = this._waitingWriters[this._nextWriter];
                delete this._waitingWriters[this._nextWriter];
                this._nextWriter = nextWriter(this);

                // Activate the waiting writer.
                activateW.call(this, false);
                return;
            }

            // Otherwise if there are waiting readers then activate them.
            for (var next = this._nextReader; Object.keys(this._waitingReaders).length > 0; next = incrementTicket(next)) {
                if (!this._waitingReaders[next])
                    continue;

                // Activate the waiting reader after deleting it from the list
                // of waiting readers.
                var activateR = this._waitingReaders[next];
                delete this._waitingReaders[next];
                activateR.call(this, false);
            }

            // All readers were activated.
            this._nextReader = 0;
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('ReadWriteLock'));
