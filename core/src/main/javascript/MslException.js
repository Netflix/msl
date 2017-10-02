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
 * Thrown when an exception occurs within the Message Security Layer.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('./util/Class.js');
	var MslConstants = require('./MslConstants.js');
	
    var MslException = module.exports = Class.create(new Error());

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
            var self = this;
            
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
                if (id < 0 || id > MslConstants.MAX_LONG_VALUE)
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
                if (self.cause && self.cause instanceof MslException)
                    return self.cause.messageId;
                return undefined;
            }

            // Construct a better stack trace.
            var originalStack = this.stack;
            function getStack() {
                var trace = self.toString();
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
         * Set the entity associated with the exception, using a master token. This
         * does nothing if the entity is already set.
         * 
         * @param {MasterToken} masterToken entity associated with the error. May be null.
         * @return {MslException} this.
         */
        setMasterToken: function setMasterToken(masterToken) {
            if (masterToken && !this.masterToken && !this.entityAuthenticationData)
                this.masterToken = masterToken;
            return this;
        },

        /**
         * Set the entity associated with the exception, using entity
         * authentication data. This does nothing if the entity is already set.
         *
         * @param {EntityAuthenticationData} entityAuthData entity associated with the error. May be null.
         * @return {MslException} this.
         */
        setEntityAuthenticationData: function setEntityAuthenticationData(entityAuthData) {
            if (entityAuthData && !this.masterToken && !this.entityAuthenticationData)
                this.entityAuthenticationData = entityAuthData;
            return this;
        },

        /**
         * Set the user associated with the exception, using a user ID token. This
         * does nothing if the user is already set.
         *
         * @param {UserIdToken} userIdToken the user ID token associated with the error. May be null.
         * @return {MslException} this.
         */
        setUserIdToken: function setUserIdToken(userIdToken) {
            if (userIdToken && !this.userIdToken && !this.userAuthenticationData)
                this.userIdToken = userIdToken;
            return this;
        },

        /**
         * Set the user associated with the exception, using user authentication
         * data. This does nothing if the user is already set.
         *
         * @param {UserAuthenticationData} userAuthData the user authentication data associated with the error. May be null.
         * @return {MslException} this.
         */
        setUserAuthenticationData: function setUserAuthenticationData(userAuthData) {
            if (userAuthData && !this.userIdToken && !this.userAuthenticationData)
                this.userAuthenticationData = userAuthData;
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
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslException'));
