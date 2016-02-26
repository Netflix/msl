/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 * Thrown when an exception occurs within the Message Security Layer.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MslException;

(function() {
    MslException = util.Class.create(new Error());

    var proto = {
        /**
         * Construct a new MSL exception with the specified error, details, and
         * cause.
         *
         * @param {MslError} error the error.
         * @param {string} details the details text. May be null or undefined.
         * @param {Error} cause the cause. May be null or undefined.
         * @constructor
         */
        init: function init(error, details, cause) {
            // Fix my stack trace.
            if (Error.captureStackTrace)
                Error.captureStackTrace(this, this.constructor);

            // Construct the message.
            var message = error.message;
            if (details)
                message += " [" + details + "]";

            // Hide the message ID inside this scope.
            var messageId;
            /**
             * Set the message ID of the message associated with the exception. This
             * does nothing if the message ID is already set.
             *
             * @param id message ID of the message associated with this error.
             */
            function setMessageId(id) {
                if (id < 0 || id > MslConstants$MAX_LONG_VALUE)
                    throw new RangeError("Message ID " + id + " is outside the valid range.");
                if (!getMessageId())
                    messageId = id;
            }

            /**
             * Returns the message ID of the message associated with the exception. May
             * be null if there is no message associated or the exception was thrown
             * before extracting the message ID.
             *
             * @return the message ID or null/undefined.
             */
            function getMessageId() {
                if (messageId)
                    return messageId;
                if (this.cause && this.cause instanceof MslException)
                    return this.cause.messageId;
                return undefined;
            }

            // Construct a better stack trace.
            var originalStack = this.stack;
            function getStack() {
                var trace = this.toString();
                if (originalStack)
                    trace += "\n" + originalStack;
                if (cause && cause.stack)
                    trace += "\nCaused by " + cause.stack;
                return trace;
            }

            // The properties.
            var props = {
                message: { value: message, writable: false, configurable: true },
                error: { value: error, writable: false, configurable: true },
                cause: { value: cause, writable: false, configurable: true },
                name: { value: "MslException", writable: false, configurable: true },
                masterToken: { value: null, writable: true, configurable: false },
                entityAuthenticationData: { value: null, writable: true, configurable: false },
                userIdToken: { value: null, writable: true, configurable: false },
                userAuthenticationData: { value: null, writable: true, configurable: false },
                messageId: { get: getMessageId, set: setMessageId, configurable: true },
                stack: { get: getStack, configurable: true }
            };
            Object.defineProperties(this, props);
        },

        /**
         * Set the entity associated with the exception. This does nothing if the
         * entity is already set.
         *
         * @param {?MasterToken|?EntityAuthenticationData} entity entity associated with the error. May be null.
         * @return {MslException} this.
         */
        setEntity: function setEntity(entity) {
            if (entity && !this.masterToken && !this.entityAuthenticationData) {
                if (entity instanceof MasterToken)
                    this.masterToken = entity;
                else if (entity instanceof EntityAuthenticationData)
                    this.entityAuthenticationData = entity;
            }
            return this;
        },

        /**
         * Set the master token associated with the exception.
         *
         * @param {MasterToken} entity masterToken associated with the error. May be null.
         * @return {MslException} this.
         */
        setMasterToken: function setMasterToken(entity) {
            this.masterToken = entity;
            return this;
        },

        /**
         * Set the entity associated with the exception.
         *
         * @param {EntityAuthenticationData} entity entity auth data associated with the error. May be null.
         * @return {MslException} this.
         */
        setEntityAuthenticationData: function setEntityAuthenticationData(entity) {
            this.entityAuthenticationData = entity;
            return this;
        },

        /**
         * Set the userAuthenticationData associated with the exception.
         *
         * @param {UserAuthenticationData} user user associated with the error. May be null.
         * @return {MslException} this.
         */
        setUserAuthenticationData: function setUserAuthenticationData(user) {
            this.userAuthenticationData = user;
            return this;
        },

        /**
         * Set the userIdToken associated with the exception.
         *
         * @param {UserIdToken} user userIdToken associated with the error. May be null.
         * @return {MslException} this.
         */
        setUserIdToken: function setUserIdToken(user) {
            this.userIdToken = user;
            return this;
        },

        /**
         * Set the message ID of the message associated with the exception. This
         * does nothing if the message ID is already set.
         *
         * @param {number} id message ID of the message associated with this error.
         * @return {MslException} this.
         */
        setMessageId: function setMessageId(id) {
            this.messageId = id;
            return this;
        },

        /**
         * @return a string containing the exception type and message.
         */
        toString: function toString() {
            return this.name + ': ' + this.message;
        }
    };

    // Attach methods.
    MslException.mixin(proto);
})();
