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
package com.netflix.msl.msg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.util.MslContext;

/**
 * <p>A message factory is used to create message streams and builders.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageFactory {
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
     * @param ctx MSL context.
     * @param source MSL input stream.
     * @param keyRequestData key request data to use when processing key
     *        response data.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be or if it has been revoked.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
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
    public MessageInputStream createInputStream(final MslContext ctx, final InputStream source, final Set<KeyRequestData> keyRequestData, final Map<String,ICryptoContext> cryptoContexts) throws IOException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslUserIdTokenException, MslMessageException, MslException {
        return new MessageInputStream(ctx, source, keyRequestData, cryptoContexts);
    }

    /**
     * Construct a new error message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream.
     * 
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header error header.
     * @param format the MSL encoder format.
     * @throws IOException if there is an error writing the header.
     */
    public MessageOutputStream createOutputStream(final MslContext ctx, final OutputStream destination, final ErrorHeader header, final MslEncoderFormat format) throws IOException {
        return new MessageOutputStream(ctx, destination, header, format);
    }

    /**
     * Construct a new message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream. The most preferred compression algorithm and encoder format
     * supported by the local entity and message header will be used.
     * 
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header message header.
     * @param cryptoContext payload data crypto context.
     * @throws IOException if there is an error writing the header.
     */
    public MessageOutputStream createOutputStream(final MslContext ctx, final OutputStream destination, final MessageHeader header, final ICryptoContext cryptoContext) throws IOException {
        return new MessageOutputStream(ctx, destination, header, cryptoContext);
    }

    /**
     * Construct a new message builder for a response.
     *
     * @param ctx the MSL context.
     * @param request message header.
     * @throws IOException if there is an error writing the header.
     */
    public MessageBuilder createResponseMessageBuilder(final MslContext ctx, final MessageHeader request) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslUserAuthException, MslException, InterruptedException {
        return MessageBuilder.createResponse(ctx, request);
    }

    /**
     * Creates a message builder and message context appropriate for re-sending
     * the original message in response to the received error.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param sent result of original sent message.
     * @param errorHeader received error header.
     * @return the message builder and message context that should be used to
     *         re-send the original request in response to the received error
     *         or null if the error cannot be handled (i.e. should be returned
     *         to the application).
     * @throws MslException if there is an error creating the message.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token lock (user re-authentication only).
     */
    public ErrorHeader createErrorResponse(final MslContext ctx, final Long requestMessageId, final MslError error, final String userMessage) throws MslCryptoException, MslEntityAuthException, MslMessageException {
        return MessageBuilder.createErrorResponse(ctx, requestMessageId, error, userMessage);
    }
}

