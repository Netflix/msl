/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * <p>A message builder provides methods for building messages.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";

	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslException = require('../MslException.js');
	var MessageCapabilities = require('../msg/MessageCapabilities.js');
	var MessageBuilder = require('../msg/MessageBuilder.js');

    var IdempotentResponseMessageBuilder = module.exports = MessageBuilder.extend({
        /**
         * Create a new message builder that will craft a new message in response
         * to another message without issuing or renewing any master tokens or user
         * ID tokens. The constructed message may be used as a request.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageHeader} requestHeader message header to respond to.
         * @param {{result: function(IdempotentResopnseMessageBuilder), error: function(Error)}}
         *        callback the callback that will receive the message builder or
         *        any thrown exceptions.
         * @throws MslCryptoException if there is an error accessing the remote
         *         entity identity.
         * @throws MslException if any of the request's user ID tokens is not bound
         *         to its master token.
         */
        init: function init(ctx, requestHeader, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                var masterToken = requestHeader.masterToken;
                var entityAuthData = requestHeader.entityAuthenticationData;
                var userIdToken = requestHeader.userIdToken;
                var userAuthData = requestHeader.userAuthenticationData;

                // The response message ID must be equal to the request message ID + 1.
                var requestMessageId = requestHeader.messageId;
                var messageId = MessageBuilder.incrementMessageId(requestMessageId);

                // Compute the intersection of the request and response message
                // capabilities.
                var capabilities = MessageCapabilities.intersection(requestHeader.messageCapabilities, ctx.getMessageCapabilities());

                // Create the message builder.
                //
                // Peer-to-peer responses swap the tokens.
                try {
                    var keyResponseData = requestHeader.keyResponseData;
                    var serviceTokens = requestHeader.serviceTokens;
                    if (ctx.isPeerToPeer()) {
                        var peerMasterToken = (keyResponseData) ? keyResponseData.masterToken : requestHeader.peerMasterToken;
                        var peerUserIdToken = requestHeader.peerUserIdToken;
                        var peerServiceTokens = requestHeader.peerServiceTokens;
                        this.initializeMessageBuilder(ctx, messageId, capabilities, entityAuthData, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, null);
                        return this;
                    } else {
                        var localMasterToken = (keyResponseData) ? keyResponseData.masterToken : masterToken;
                        this.initializeMessageBuilder(ctx, messageId, capabilities, entityAuthData, localMasterToken, userIdToken, serviceTokens, null, null, null, null);
                        return this;
                    }
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(masterToken);
                        e.setEntityAuthenticationData(entityAuthData);
                        e.setUserIdToken(userIdToken);
                        e.setUserAuthenticationData(userAuthData);
                        e.setMessageId(requestMessageId);
                    }
                    throw e;
                }
            }, self);
        }

    });

    /**
     * Create a new message builder that will craft a new message in response
     * to another message without issuing or renewing any master tokens or user
     * ID tokens. The constructed message may be used as a request.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MessageHeader} requestHeader message header to respond to.
     * @param {{result: function(IdempotentResopnseMessageBuilder), error: function(Error)}}
     *        callback the callback that will receive the message builder or
     *        any thrown exceptions.
     * @throws MslCryptoException if there is an error accessing the remote
     *         entity identity.
     * @throws MslException if any of the request's user ID tokens is not bound
     *         to its master token.
     */
    var IdempotentResponseMessageBuilder$create = function IdempotentResponseMessageBuilder$create(ctx, requestHeader, callback) {
        new IdempotentResponseMessageBuilder(ctx, requestHeader, callback);
    }

    module.exports.create = IdempotentResponseMessageBuilder$create;

})(require, (typeof module !== 'undefined') ? module : mkmodule('IdempotentResponseMessageBuilder'));
