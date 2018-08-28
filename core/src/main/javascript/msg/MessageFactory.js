/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>The message factory is used to create message-related objects.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var MessageInputStream = require('../msg/MessageInputStream.js');
	var MessageOutputStream = require('../msg/MessageOutputStream.js');
	
	var MessageFactory = module.exports = Class.create({
	    /**
	     * <p>Construct a new message input stream. The header is parsed.</p>
	     *
	     * <p>If key request data is provided and a matching key response data is
	     * found in the message header the key exchange will be performed to
	     * process the message payloads.</p>
	     *
	     * <p>Service tokens will be decrypted and verified with the provided crypto
	     * contexts identified by token name. A default crypto context may be
	     * provided by using the empty string as the token name; if a token name is
	     * not explcitly mapped onto a crypto context, the default crypto context
	     * will be used.</p>
	     *
	     * @param {MslContext} ctx MSL context.
	     * @param {InputStream} source MSL input stream.
	     * @param {Array.<KeyRequestData>} keyRequestData key request data to use when processing key
	     *        response data.
	     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
	     *        contexts used to decrypt and verify service tokens.
	     * @param {number} timeout read timeout in milliseconds.
	     * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive the message input
	     *        stream, or any thrown exceptions.
	     * @throws IOException if there is a problem reading from the input stream.
	     * @throws MslEncodingException if there is an error parsing the message.
	     * @throws MslCryptoException if there is an error decrypting or verifying
	     *         the header or creating the message payload crypto context.
	     * @throws MslEntityAuthException if unable to create the entity
	     *         authentication data.
	     * @throws MslUserAuthException if unable to create the user authentication
	     *         data.
	     * @throws MslMasterTokenException if the master token is not trusted and
	     *         needs to be.
	     * @throws MslKeyExchangeException if there is an error with the key
	     *         request data or key response data or the key exchange scheme is
	     *         not supported.
	     * @throws MslMessageException if the message does not contain an entity
	     *         authentication data or a master token, the header data is
	     *         missing or invalid, or the message ID is negative, or the
	     *         message is not encrypted and contains user authentication data,
	     *         or if the message master token is expired and the message is not
	     *         renewable.
	     * @throws MslException if the message does not contain an entity
	     *         authentication data or a master token, or a token is improperly
	     *         bound to another token.
	     */
	    createInputStream: function createInputStream(ctx, source, keyRequestData, cryptoContexts, timeout, callback) {
	        MessageInputStream.create(ctx, source, keyRequestData, cryptoContexts, timeout, callback);
	    },
	
	    /**
	     * Construct a new message output stream. The header is output
	     * immediately by calling {@code #flush()} on the destination output
	     * stream. The most preferred compression algorithm supported by the
	     * local entity and message header will be used.
	     *
	     * @param {MslContext} ctx the MSL context.
	     * @param {OutputStream} destination MSL output stream.
	     * @param {MessageHeader|ErrorHeader} header message or error header.
	     * @param {?ICryptoContext} cryptoContext payload data crypto context.
	     *        Required if a message header is provided.
	     * @param {?MslEncoderFormat} format MSL encoder format. Required if an
	     *        error header is provided.
	     * @param {number} timeout write timeout in milliseconds.
	     * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive the message output
	     *        stream, or any thrown exceptions.
	     * @throws IOException if there is an error writing the header.
	     */
	    createOutputStream: function createOutputStream(ctx, destination, header, cryptoContext, format, timeout, callback) {
	        MessageOutputStream.create(ctx, destination, header, cryptoContext, format, timeout, callback);
	    },

	    /**
	     * Construct a new message builder for a response.
	     *
	     * @param {MslContext} ctx the MSL context.
	     * @param request message header.
	     * @param {{result: function(MessageBuilder), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive the message builder,
	     *        or any thrown exceptions.
	     * @throws IOException if there is an error writing the header.
	     */
	    createResponse: function createResponse(ctx, requestHeader, callback) {
	        MessageBuilder.createResponse(ctx, requestHeader, callback);
	    },

	    /**
	     * <p>Create a new message builder that will craft a new error message in
	     * response to another message. If the message ID of the request is not
	     * specified (i.e. unknown) then a random message ID will be generated.</p>
	     *
	     * @param {MslContext} ctx MSL context.
	     * @param {?number} requestMessageId message ID of request. May be null.
	     * @param {MslError} error the MSL error.
	     * @param {string} userMessage localized user-consumable error message. May be null.
	     * @param {{result: function(ErrorHeader), error: function(Error)}}
	     *        callback the callback that will receive the error header or any
	     *        thrown exceptions.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the message.
	     * @throws MslEntityAuthException if there is an error with the entity
	     *         authentication data.
	     * @throws MslMessageException if no entity authentication data was
	     *         returned by the MSL context.
	     */
	    createErrorResponse: function createErrorResponse(ctx, requestMessageId, error, userMessage, callback) {
	        MessageBuilder.createErrorResponse(ctx, requestMessageId, error, userMessage, callback);
	    }
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageFactory'));
