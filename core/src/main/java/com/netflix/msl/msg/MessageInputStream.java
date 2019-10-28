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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.io.MslTokenizer;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;

/**
 * <p>A MSL message consists of a single MSL header followed by one or more
 * payload chunks carrying application data. Each payload chunk is individually
 * packaged but sequentially ordered. No payload chunks may be included in an
 * error message.</p>
 *
 * <p>Data is read until an end-of-message payload chunk is encountered or an
 * error occurs. Closing a {@code MessageInputStream} does not close the source
 * input stream in case additional MSL messages will be read.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageInputStream extends InputStream {
    /**
     * <p>Return the crypto context resulting from key response data contained
     * in the provided header.</p>
     *
     * <p>The {@link MslException}s thrown by this method will not have the
     * entity or user set.</p>
     *
     * @param ctx MSL context.
     * @param header header.
     * @param keyRequestData key request data for key exchange.
     * @return the crypto context or null if the header does not contain key
     *         response data or is for an error message.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     */
    private static ICryptoContext getKeyxCryptoContext(final MslContext ctx, final MessageHeader header, final Set<KeyRequestData> keyRequestData) throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
        // Pull the header data.
        final MessageHeader messageHeader = header;
        final MasterToken masterToken = messageHeader.getMasterToken();
        final KeyResponseData keyResponse = messageHeader.getKeyResponseData();

        // If there is no key response data then return null.
        if (keyResponse == null)
            return null;

        // If the key response data master token is decrypted then use the
        // master token keys to create the crypto context.
        final MasterToken keyxMasterToken = keyResponse.getMasterToken();
        if (keyxMasterToken.isDecrypted())
            return new SessionCryptoContext(ctx, keyxMasterToken);

        // Perform the key exchange.
        final KeyExchangeScheme responseScheme = keyResponse.getKeyExchangeScheme();
        final KeyExchangeFactory factory = ctx.getKeyExchangeFactory(responseScheme);
        if (factory == null)
            throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, responseScheme.name());

        // Attempt the key exchange but if it fails then try with the next
        // key request data before giving up.
        MslException keyxException = null;
        final Iterator<KeyRequestData> keyRequests = keyRequestData.iterator();
        while (keyRequests.hasNext()) {
            final KeyRequestData keyRequest = keyRequests.next();
            final KeyExchangeScheme requestScheme = keyRequest.getKeyExchangeScheme();

            // Skip incompatible key request data.
            if (!responseScheme.equals(requestScheme))
                continue;

            try {
                return factory.getCryptoContext(ctx, keyRequest, keyResponse, masterToken);
            } catch (final MslKeyExchangeException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslEncodingException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslMasterTokenException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslEntityAuthException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            }
        }

        // We did not perform a successful key exchange. If we caught an
        // exception then throw that exception now.
        if (keyxException != null) {
            if (keyxException instanceof MslKeyExchangeException)
                throw (MslKeyExchangeException)keyxException;
            if (keyxException instanceof MslEncodingException)
                throw (MslEncodingException)keyxException;
            if (keyxException instanceof MslMasterTokenException)
                throw (MslMasterTokenException)keyxException;
            if (keyxException instanceof MslEntityAuthException)
                throw (MslEntityAuthException)keyxException;
            throw new MslInternalException("Unexpected exception caught during key exchange.", keyxException);
        }

        // If we did not perform a successful key exchange then the
        // payloads will not decrypt properly. Throw an exception.
        throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, Arrays.toString(keyRequestData.toArray()));
    }

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
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
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
    public MessageInputStream(final MslContext ctx, final InputStream source, final Set<KeyRequestData> keyRequestData, final Map<String,ICryptoContext> cryptoContexts) throws IOException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslUserIdTokenException, MslMessageException, MslException {
        // Parse the header.
        this.ctx = ctx;
        this.source = source;
        final MslObject mo;
        try {
            this.tokenizer = this.ctx.getMslEncoderFactory().createTokenizer(source);
            if (!this.tokenizer.more(-1))
                throw new MslEncodingException(MslError.MESSAGE_DATA_MISSING);
            mo = this.tokenizer.nextObject(-1);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "header", e);
        }
        this.header = Header.parseHeader(ctx, mo, cryptoContexts);

        try {
            // For error messages there are no key exchange or payload crypto
            // contexts.
            if (this.header instanceof ErrorHeader) {
                this.keyxCryptoContext = null;
                this.cryptoContext = null;
                return;
            }

            // Grab the key exchange crypto context, if any.
            final MessageHeader messageHeader = (MessageHeader)this.header;
            this.keyxCryptoContext = getKeyxCryptoContext(ctx, messageHeader, keyRequestData);

            // In peer-to-peer mode or in trusted network mode with no key
            // exchange the payload crypto context equals the header crypto
            // context.
            if (ctx.isPeerToPeer() || this.keyxCryptoContext == null)
                this.cryptoContext = messageHeader.getCryptoContext();

            // Otherwise the payload crypto context equals the key exchange
            // crypto context.
            else
                this.cryptoContext = this.keyxCryptoContext;

            // If this is a handshake message but it is not renewable or does
            // not contain key request data then reject the message.
            if (messageHeader.isHandshake() &&
                (!messageHeader.isRenewable() || messageHeader.getKeyRequestData().isEmpty()))
            {
                throw new MslMessageException(MslError.HANDSHAKE_DATA_MISSING, messageHeader.toString());
            }

            // If I am in peer-to-peer mode or the master token is verified
            // (i.e. issued by the local entity which is therefore a trusted
            // network server) then perform the master token checks.
            final MasterToken masterToken = messageHeader.getMasterToken();
            if (masterToken != null && (ctx.isPeerToPeer() || masterToken.isVerified())) {
                // If the master token has been revoked then reject the
                // message.
                final TokenFactory factory = ctx.getTokenFactory();
                final MslError revoked = factory.isMasterTokenRevoked(ctx, masterToken);
                if (revoked != null)
                    throw new MslMasterTokenException(revoked, masterToken);

                // If the user ID token has been revoked then reject the
                // message. We know the master token is not null and that it is
                // verified so we assume the user ID token is as well.
                final UserIdToken userIdToken = messageHeader.getUserIdToken();
                if (userIdToken != null) {
                    final MslError uitRevoked = factory.isUserIdTokenRevoked(ctx, masterToken, userIdToken);
                    if (uitRevoked != null)
                        throw new MslUserIdTokenException(uitRevoked, userIdToken);
                }

                // If the master token is expired...
                if (masterToken.isExpired(null)) {
                    // If the message is not renewable or does not contain key
                    // request data then reject the message.
                    if (!messageHeader.isRenewable())
                        throw new MslMessageException(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE, messageHeader.toString());
                    else if (messageHeader.getKeyRequestData().isEmpty())
                        throw new MslMessageException(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA, messageHeader.toString());

                    // If the master token will not be renewed by the token
                    // factory then reject the message.
                    //
                    // This throws an exception if the master token is not
                    // renewable.
                    final MslError notRenewable = factory.isMasterTokenRenewable(ctx, masterToken);
                    if (notRenewable != null)
                        throw new MslMessageException(notRenewable, "Master token is expired and not renewable.");
                }
            }

            // If the message is non-replayable (it is not from a trusted
            // network server).
            final Long nonReplayableId = messageHeader.getNonReplayableId();
            if (nonReplayableId != null) {
                // ...and does not include a master token then reject the
                // message.
                if (masterToken == null)
                    throw new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE, messageHeader.toString());

                // If the non-replayable ID is not accepted then notify the
                // sender.
                final TokenFactory factory = ctx.getTokenFactory();
                final MslError replayed = factory.acceptNonReplayableId(ctx, masterToken, nonReplayableId);
                if (replayed != null)
                    throw new MslMessageException(replayed, messageHeader.toString());
            }
        } catch (final MslException e) {
            if (this.header instanceof MessageHeader) {
                final MessageHeader messageHeader = (MessageHeader)this.header;
                e.setMasterToken(messageHeader.getMasterToken());
                e.setEntityAuthenticationData(messageHeader.getEntityAuthenticationData());
                e.setUserIdToken(messageHeader.getUserIdToken());
                e.setUserAuthenticationData(messageHeader.getUserAuthenticationData());
                e.setMessageId(messageHeader.getMessageId());
            } else {
                final ErrorHeader errorHeader = (ErrorHeader)this.header;
                e.setEntityAuthenticationData(errorHeader.getEntityAuthenticationData());
                e.setMessageId(errorHeader.getMessageId());
            }
            throw e;
        }
    }

    /* (non-Javadoc)
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        // Do not close the source because we might want to reuse it.
        super.finalize();
    }

    /**
     * Retrieve the next MSL object.
     *
     * @return the next MSL object or null if none remaining.
     * @throws MslEncodingException if there is a problem parsing the data.
     */
    protected MslObject nextMslObject() throws MslEncodingException {
        // Make sure this message is allowed to have payload chunks.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            throw new MslInternalException("Read attempted with error message.");

        // If we previously reached the end of the message, don't try to read
        // more.
        if (eom)
            return null;

        // Otherwise read the next MSL object.
        try {
            if (!tokenizer.more(-1)) {
                eom = true;
                return null;
            }
            return tokenizer.nextObject(-1);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payloadchunk", e);
        }
    }

    /**
     * Create a new payload chunk
     *
     * @param ctx the MSL context.
     * @param mo the MSL object.
     * @param cryptoContext the crypto context.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    protected PayloadChunk createPayloadChunk(final MslContext ctx, final MslObject mo, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        return new PayloadChunk(ctx, mo, cryptoContext);
    }

    /**
     * Retrieve the next payload chunk data.
     *
     * @return the next payload chunk data or null if none remaining.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslInternalException if attempting to access payloads of an
     *         error message.
     * @throws MslException if there is an error uncompressing the data.
     */
    protected ByteArrayInputStream nextData() throws MslCryptoException, MslEncodingException, MslMessageException, MslInternalException, MslException {
        // Make sure this message is allowed to have payload chunks.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            throw new MslInternalException("Read attempted with error message.");

        // If reading buffered data return the next buffered payload data.
        if (payloadIterator != null && payloadIterator.hasNext())
            return payloadIterator.next();

        // Otherwise read the next payload.
        final MslObject mo = nextMslObject();
        if (mo == null) return null;
        final PayloadChunk payload = createPayloadChunk(ctx, mo, cryptoContext);

        // Make sure the payload belongs to this message and is the one we are
        // expecting.
        final MasterToken masterToken = messageHeader.getMasterToken();
        final EntityAuthenticationData entityAuthData = messageHeader.getEntityAuthenticationData();
        final UserIdToken userIdToken = messageHeader.getUserIdToken();
        final UserAuthenticationData userAuthData = messageHeader.getUserAuthenticationData();
        if (payload.getMessageId() != messageHeader.getMessageId()) {
            throw new MslMessageException(MslError.PAYLOAD_MESSAGE_ID_MISMATCH, "payload mid " + payload.getMessageId() + " header mid " + messageHeader.getMessageId())
                .setMasterToken(masterToken)
                .setEntityAuthenticationData(entityAuthData)
                .setUserIdToken(userIdToken)
                .setUserAuthenticationData(userAuthData);
        }
        if (payload.getSequenceNumber() != payloadSequenceNumber) {
            throw new MslMessageException(MslError.PAYLOAD_SEQUENCE_NUMBER_MISMATCH, "payload seqno " + payload.getSequenceNumber() + " expected seqno " + payloadSequenceNumber)
                .setMasterToken(masterToken)
                .setEntityAuthenticationData(entityAuthData)
                .setUserIdToken(userIdToken)
                .setUserAuthenticationData(userAuthData);
        }
        ++payloadSequenceNumber;

        // FIXME remove this logic once the old handshake inference logic
        // is no longer supported.
        // Check for a handshake if this is the first payload chunk.
        if (handshake == null) {
            handshake = (messageHeader.isRenewable() && !messageHeader.getKeyRequestData().isEmpty() &&
                payload.isEndOfMessage() && payload.getData().length == 0);
        }

        // Check for end of message.
        if (payload.isEndOfMessage())
            eom = true;

        // If mark was called save the payload in the buffer. We have to unset
        // the payload iterator since we're adding to the payloads list.
        final ByteArrayInputStream data = new ByteArrayInputStream(payload.getData());
        if (payloads != null) {
            payloads.add(data);
            payloadIterator = null;
        }
        return data;
    }

    /**
     * Returns true if the message is a handshake message.
     *
     * FIXME
     * This method should be removed by a direct query of the message header
     * once the old behavior of inferred handshake messages based on a single
     * empty payload chunk is no longer supported.
     *
     * @return true if the message is a handshake message.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslInternalException if attempting to access payloads of an
     *         error message.
     * @throws MslException if there is an error uncompressing the data.
     */
    public boolean isHandshake() throws MslCryptoException, MslEncodingException, MslMessageException, MslInternalException, MslException {
        final MessageHeader messageHeader = getMessageHeader();

        // Error messages are not handshake messages.
        if (messageHeader == null) return false;

        // If the message header has its handshake flag set return true.
        if (messageHeader.isHandshake()) return true;

        // If we haven't read a payload we don't know if this is a handshake
        // message or not. This also implies the current payload is null.
        if (handshake == null) {
            try {
                // nextData() will set the value of handshake if a payload is
                // found.
                currentPayload = nextData();
                if (currentPayload == null)
                    handshake = Boolean.FALSE;
            } catch (final MslException e) {
                // Save the exception to be thrown next time read() is called.
                readException = new IOException("Error reading the payload chunk.", e);
                throw e;
            }
        }

        // Return the current handshake status.
        return handshake.booleanValue();
    }

    /**
     * @return the message header. Will be null for error messages.
     */
    public MessageHeader getMessageHeader() {
        if (header instanceof MessageHeader)
            return (MessageHeader)header;
        return null;
    }

    /**
     * @return the error header. Will be null except for error messages.
     */
    public ErrorHeader getErrorHeader() {
        if (header instanceof ErrorHeader)
            return (ErrorHeader)header;
        return null;
    }

    /**
     * Returns the sender's entity identity. The identity will be unknown if
     * the local entity is a trusted network client and the message was sent by
     * a trusted network server using the local entity's master token.
     *
     * @return the sender's entity identity or null if unknown.
     * @throws MslCryptoException if there is a crypto error accessing the
     *         entity identity;
     */
    public String getIdentity() throws MslCryptoException {
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader != null) {
            final MasterToken masterToken = messageHeader.getMasterToken();
            if (masterToken != null)
                return masterToken.getIdentity();
            return messageHeader.getEntityAuthenticationData().getIdentity();
        }
        final ErrorHeader errorHeader = getErrorHeader();
        return errorHeader.getEntityAuthenticationData().getIdentity();
    }

    /**
     * Returns the user associated with the message. The user will be unknown
     * if the local entity is a trusted network client and the message was sent
     * by a trusted network server.
     *
     * @return the user associated with the message or null if unknown.
     */
    public MslUser getUser() {
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            return null;
        return messageHeader.getUser();
    }

    /**
     * @return the payload crypto context. Will be null for error messages.
     */
    public ICryptoContext getPayloadCryptoContext() {
        return cryptoContext;
    }

    /**
     * @return the key exchange crypto context. Will be null if no key response
     *         data was returned in this message and for error messages.
     */
    public ICryptoContext getKeyExchangeCryptoContext() {
        return keyxCryptoContext;
    }
    
    /**
     * Returns true if the payload application data is encrypted. This will be
     * true if the entity authentication scheme provides encryption or if
     * session keys were used. Returns false for error messages which do not
     * have any payload chunks.
     * 
     * @return true if the payload application data is encrypted. Will be false
     *         for error messages.
     */
    public boolean encryptsPayloads() {
        // Return false for error messages.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            return false;
        
        // If the message uses entity authentication data for an entity
        // authentication scheme that provides encryption, return true.
        final EntityAuthenticationData entityAuthData = messageHeader.getEntityAuthenticationData();
        if (entityAuthData != null && entityAuthData.getScheme().encrypts())
            return true;
        
        // If the message uses a master token, return true.
        final MasterToken masterToken = messageHeader.getMasterToken();
        if (masterToken != null)
            return true;
        
        // If the message includes key response data, return true.
        final KeyResponseData keyResponseData = messageHeader.getKeyResponseData();
        if (keyResponseData != null)
            return true;
        
        // Otherwise return false.
        return false;
    }
    
    /**
     * Returns true if the payload application data is integrity protected.
     * This will be true if the entity authentication scheme provides integrity
     * protection or if session keys were used. Returns false for error
     * messages which do not have any payload chunks.
     * 
     * @return true if the payload application data is integrity protected.
     *         Will be false for error messages.
     */
    public boolean protectsPayloadIntegrity() {
        // Return false for error messages.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            return false;
        
        // If the message uses entity authentication data for an entity
        // authentication scheme that provides integrity protection, return
        // true.
        final EntityAuthenticationData entityAuthData = messageHeader.getEntityAuthenticationData();
        if (entityAuthData != null && entityAuthData.getScheme().protectsIntegrity())
            return true;
        
        // If the message uses a master token, return true.
        final MasterToken masterToken = messageHeader.getMasterToken();
        if (masterToken != null)
            return true;
        
        // If the message includes key response data, return true.
        final KeyResponseData keyResponseData = messageHeader.getKeyResponseData();
        if (keyResponseData != null)
            return true;
        
        // Otherwise return false.
        return false;
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#available()
     */
    @Override
    public int available() throws IOException {
        // Start with the amount available in the current payload.
        if (currentPayload == null) return 0;
        int available = currentPayload.available();

        // If there is buffered data, iterate over all subsequent buffered
        // payloads.
        if (payloads != null) {
            final int startIndex = payloads.indexOf(currentPayload);
            if (startIndex != -1 && startIndex < payloads.size() - 1) {
                final Iterator<ByteArrayInputStream> nextPayloads = payloads.listIterator(startIndex + 1);
                while (nextPayloads.hasNext()) {
                    final ByteArrayInputStream payload = nextPayloads.next();
                    available += payload.available();
                }
            }
        }

        // Return available bytes.
        return available;
    }

    /**
     * By default the source input stream is not closed when this message input
     * stream is closed. If it should be closed then this method can be used to
     * dictate the desired behavior.
     *
     * @param close true if the source input stream should be closed, false if
     *        it should not.
     */
    public void closeSource(final boolean close) {
        this.closeSource = close;
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#close()
     */
    @Override
    public void close() throws IOException {
        // Close the tokenizer.
        try {
            tokenizer.close();
        } catch (final MslEncoderException e) {
            // Ignore exceptions.
        }

        // Only close the source if instructed to do so because we might want
        // to reuse the connection.
        if (closeSource) {
            source.close();
        }

        // Otherwise if this is not a handshake message or error message then
        // consume all payloads that may still be on the source input stream.
        else {
            try {
                if (!isHandshake() && getMessageHeader() != null) {
                    while (true) {
                        final ByteArrayInputStream data = nextData();
                        if (data == null) break;
                    }
                }
            } catch (final MslException e) {
                // Ignore exceptions.
            }
        }
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#mark(int)
     */
    @Override
    public void mark(final int readlimit) {
        // Remember the read limit, reset the read count.
        this.readlimit = readlimit;
        this.readcount = 0;

        // Start buffering.
        buffering = true;

        // If there is a current payload...
        if (currentPayload != null) {
            // Remove all buffered data earlier than the current payload.
            while (payloads.size() > 0 && !payloads.get(0).equals(currentPayload))
                payloads.remove(0);

            // Add the current payload if it was not already buffered.
            if (payloads.size() == 0)
                payloads.add(currentPayload);

            // Reset the iterator to continue reading buffered data from the
            // current payload.
            payloadIterator = payloads.listIterator();
            currentPayload = payloadIterator.next();

            // Set the new mark point on the current payload.
            currentPayload.mark(readlimit);
            return;
        }

        // Otherwise we've either read to the end or haven't read anything at
        // all yet. Discard all buffered data.
        payloadIterator = null;
        payloads.clear();
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#markSupported()
     */
    @Override
    public boolean markSupported() {
        return true;
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#read()
     */
    @Override
    public int read() throws IOException {
        final byte[] b = new byte[1];
        if (read(b) == -1) return -1;
        return b[0];
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#read(byte[], int, int)
     */
    @Override
    public int read(final byte[] cbuf, final int off, final int len) throws IOException {
        // Throw any cached read exception.
        if (readException != null) {
            final IOException e = readException;
            readException = null;
            throw e;
        }

        // Return end of stream immediately for handshake messages.
        try {
            if (this.isHandshake())
                return -1;
        } catch (final MslException e) {
            // FIXME
            // Unset the read exception since we are going to throw it right
            // now. This logic can go away once the old handshake logic is
            // removed.
            readException = null;
            throw new IOException("Error reading the payload chunk.", e);
        }

        // Read from payloads until we are done or cannot read anymore.
        int bytesRead = 0;
        while (bytesRead < len) {
            final int read = (currentPayload != null) ? currentPayload.read(cbuf, off + bytesRead, len - bytesRead) : -1;

            // If we read some data continue.
            if (read != -1) {
                bytesRead += read;
                continue;
            }

            // Otherwise grab the next payload data.
            try {
                currentPayload = nextData();
                if (currentPayload == null)
                    break;
            } catch (final MslException e) {
                // If we already read some data return it and save the
                // exception to be thrown next time read() is called.
                final IOException ioe = new IOException("Error reading the payload chunk.", e);
                if (bytesRead > 0) {
                    readException = ioe;
                    return bytesRead;
                }

                // Otherwise throw the exception now.
                throw ioe;
            }
        }

        // If nothing was read (but something was requested) return end of
        // stream.
        if (bytesRead == 0 && len > 0)
            return -1;

        // If buffering data increment the read count.
        if (buffering) {
            readcount += bytesRead;

            // If the read count exceeds the read limit stop buffering payloads
            // and reset the read count and limit, but retain the payload
            // iterator as we need to continue reading from any buffered data.
            if (readcount > readlimit) {
                buffering = false;
                readcount = readlimit = 0;
            }
        }

        // Return the number of bytes read.
        return bytesRead;
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#read(byte[])
     */
    @Override
    public int read(final byte[] cbuf) throws IOException {
        return read(cbuf, 0, cbuf.length);
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#reset()
     */
    @Override
    public void reset() throws IOException {
        // Do nothing if we are not buffering.
        if (!buffering)
            return;

        // Reset all payloads and initialize the payload iterator.
        //
        // We need to reset the payloads since we are going to re-read them and
        // want the correct value returned when queried for available bytes.
        for (final ByteArrayInputStream payload : payloads)
            payload.reset();
        payloadIterator = payloads.listIterator();
        if (payloadIterator.hasNext()) {
            currentPayload = payloadIterator.next();
        } else {
            currentPayload = null;
        }

        // Reset the read count.
        readcount = 0;
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#skip(long)
     */
    @Override
    public long skip(final long n) throws IOException {
        // Skip from payloads until we are done or cannot skip anymore.
        int bytesSkipped = 0;
        while (bytesSkipped < n) {
            final long skipped = (currentPayload != null) ? currentPayload.skip(n - bytesSkipped) : 0;

            // If we skipped some data continue.
            if (skipped != 0) {
                bytesSkipped += skipped;
                continue;
            }

            // Otherwise grab the next payload data.
            try {
                currentPayload = nextData();
                if (currentPayload == null)
                    break;
            } catch (final MslInternalException e) {
                throw new IOException("Cannot skip data off an error message.", e);
            } catch (final MslException e) {
                throw new IOException("Error skipping in the payload chunk.", e);
            }
        }
        return bytesSkipped;
    }

    /** MSL context. */
    private final MslContext ctx;
    /** MSL input stream. */
    private final InputStream source;
    /** MSL tokenizer. */
    private final MslTokenizer tokenizer;

    /** Header. */
    private final Header header;
    /** Payload crypto context. */
    private final ICryptoContext cryptoContext;
    /** Key exchange crypto context. */
    private final ICryptoContext keyxCryptoContext;

    /** Current payload sequence number. */
    private long payloadSequenceNumber = 1;
    /** End of message reached. */
    private boolean eom = false;
    /** Handshake message. */
    private Boolean handshake = null;

    /** True if the source input stream should be closed. */
    private boolean closeSource = false;

    /** True if buffering. */
    private boolean buffering = false;
    /**
     * Buffered payload data.
     *
     * This list contains all payload data that has been referenced since the
     * last call to {@link #mark(int)}.
     */
    private final List<ByteArrayInputStream> payloads = new LinkedList<ByteArrayInputStream>();;
    /** Buffered payload data iterator. Not null if reading buffered data. */
    private ListIterator<ByteArrayInputStream> payloadIterator = null;
    /** Mark read limit. */
    private int readlimit = 0;
    /** Mark read count. */
    private int readcount = 0;
    /** Current payload chunk data. */
    private ByteArrayInputStream currentPayload = null;

    /** Cached read exception. */
    private IOException readException = null;
}
