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
package com.netflix.msl.msg;

import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslException;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;

/**
 * <p>Idempotent message builder.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class IdempotentResponseMessageBuilder extends MessageBuilder {
    /**
     * Create a new message builder that will craft a new message in response
     * to another message without issuing or renewing any master tokens or user
     * ID tokens. The constructed message may be used as a request.
     *
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @throws MslCryptoException if there is an error accessing the remote
     *         entity identity.
     * @throws MslException if any of the request's user ID tokens is not bound
     *         to its master token.
     */
    public IdempotentResponseMessageBuilder(final MslContext ctx, final MessageHeader requestHeader) throws MslCryptoException, MslException {
        super(ctx);
        final MasterToken masterToken = requestHeader.getMasterToken();
        final EntityAuthenticationData entityAuthData = requestHeader.getEntityAuthenticationData();
        final UserIdToken userIdToken = requestHeader.getUserIdToken();
        final UserAuthenticationData userAuthData = requestHeader.getUserAuthenticationData();

        // The response message ID must be equal to the request message ID + 1.
        final long requestMessageId = requestHeader.getMessageId();
        final long messageId = incrementMessageId(requestMessageId);

        // Compute the intersection of the request and response message
        // capabilities.
        final MessageCapabilities capabilities = MessageCapabilities.intersection(requestHeader.getMessageCapabilities(), ctx.getMessageCapabilities());

        // Create the message builder.
        //
        // Peer-to-peer responses swap the tokens.
        try {
            final KeyResponseData keyResponseData = requestHeader.getKeyResponseData();
            final Set<ServiceToken> serviceTokens = requestHeader.getServiceTokens();
            if (ctx.isPeerToPeer()) {
                final MasterToken peerMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : requestHeader.getPeerMasterToken();
                final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                final Set<ServiceToken> peerServiceTokens = requestHeader.getPeerServiceTokens();
                initializeMessageBuilder(ctx, messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, null);
            } else {
                final MasterToken localMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : masterToken;
                initializeMessageBuilder(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, null, null, null, null);
            }
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            e.setMessageId(requestMessageId);
            throw e;
        }
    }
}
