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

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>The message context provides the information that should be used to
 * construct a single message. Each message should have its own context.</p>
 * 
 * <p>All context methods may be called multiple times except for
 * {@code #write(OutputStream)} which is guaranteed to be called only once.
 * (The written data will be cached in memory in case the message needs to be
 * resent.)</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface MessageContext {
    /** Re-authentication reason codes. */
    public static enum ReauthCode {
        /** The user authentication data did not identify a user. */
        USERDATA_REAUTH(ResponseCode.USERDATA_REAUTH),
        /** The single-sign-on token was rejected as bad, invalid, or expired. */
        SSOTOKEN_REJECTED(ResponseCode.SSOTOKEN_REJECTED),
        ;
        
        /**
         * @return the re-authentication code corresponding to the response
         *         code.
         * @throws IllegalArgumentException if the response code does not map
         *         onto a re-authentication code.
         */
        public static ReauthCode valueOf(final ResponseCode code) {
            for (final ReauthCode value : ReauthCode.values()) {
                if (value.code == code)
                    return value;
            }
            throw new IllegalArgumentException("Unknown reauthentication code value " + code + ".");
        }
        
        /**
         * Create a new re-authentication code mapped from the specified
         * response code.
         * 
         * @param code the response code for the re-authentication code.
         */
        private ReauthCode(final ResponseCode code) {
            this.code = code;
        }
        
        /**
         * @return the integer value of the response code.
         */
        public int intValue() {
            return code.intValue();
        }
        
        /** The response code value. */
        private final ResponseCode code;
    }
    
    /**
     * <p>Called when receiving a message to process service tokens.</p>
     * 
     * <p>This method should return a map of crypto contexts by service token
     * name for all known service tokens. If the service token name is not
     * found then the crypto context mapped onto the empty string will be
     * used if found.</p>
     * 
     * @return the service token crypto contexts.
     */
    public Map<String,ICryptoContext> getCryptoContexts();
    
    /**
     * <p>Called to identify the expected remote entity identity. If the remote
     * entity identity is not known this method must return {@code null}.</p> 
     * 
     * <p>Trusted network servers may always return {@code null}.</p>
     * 
     * @return the remote entity identity or {@code null} if the identity is
     *         not known.
     */
    public String getRemoteEntityIdentity();
    
    /**
     * <p>Called to determine if the message application data must be
     * encrypted.</p>
     * 
     * @return true if the application data must be encrypted.
     */
    public boolean isEncrypted();
    
    /**
     * <p>Called to determine if the message application data must be integrity
     * protected.</p>
     * 
     * @return true if the application data must be integrity protected.
     */
    public boolean isIntegrityProtected();
    
    /**
     * <p>Called to determine if a message should be marked as non-replayable.</p>
     * 
     * <p>Trusted network servers must always return {@code false}.</p>
     * 
     * @return true if the application data should not be carried in a
     *         replayable message.
     */
    public boolean isNonReplayable();
    
    /**
     * <p>Called to determine if a message is requesting a master token, user
     * ID token, or service tokens.</p>
     * 
     * <p>Trusted network servers must always return {@code false}.</p>
     * 
     * @return true if the message must have a master token and user ID token
     *         (if associated with a user) or must be carried in a renewable
     *         message to acquire said tokens.
     */
    public boolean isRequestingTokens();
    
    /**
     * <p>Called to identify the local user the message should be sent with. If
     * a user ID token exists for this user it will be used.</p>
     * 
     * <p>Trusted network servers must always return {@code null}.</p>
     * 
     * <p>Any non-null value returned by this method must match the local user
     * associated with the user authentication data returned by
     * {@link #getUserAuthData(ReauthCode, boolean, boolean)}.</p>
     * 
     * <p>This method may return a non-null value when
     * {@link #getUserAuthData(ReauthCode, boolean, boolean)} will return null
     * if the message should be associated with a user but there is no user
     * authentication data. For example during new user creation.</p>
     * 
     * <p>This method must return {@code null} if the message should not be
     * associated with a user and
     * {@link #getUserAuthData(ReauthCode, boolean, boolean)} will also return
     * {@code null}.</p>
     * 
     * @return the local user identity or null.
     */
    public String getUserId();
    
    /**
     * <p>Called if the user ID is not {@code null} to attach user
     * authentication data to messages.</p>
     * 
     * <p>Trusted network servers must always return {@code null}.</p>
     * 
     * <p>This method should return user authentication data if the message
     * should be associated with a user that has not already received a user ID
     * token. This may involve prompting the user for credentials. If the
     * message should not be associated with a user, a user ID token already
     * exists for the user, or if user credentials are unavailable then this
     * method should return {@code null}.</p>
     *
     * <p>The one exception is if the application wishes to re-authenticate the
     * user against the current user ID token in which case this method should
     * return user authentication data. The {@code renewable} parameter may be
     * used to limit this operation to renewable messages.</p>
     * 
     * <p>This method may be called if user re-authentication is required for
     * the transaction to complete. If the application knows that user
     * authentication is required for the request being sent and is unable to
     * provide user authentication data then it should attempt to cancel the
     * request and return {@code null}.</p>
     * 
     * <p>If the {@code reauthCode} parameter is non-{@code null} then new user
     * authentication data should be returned for this and all subsequent calls.
     * The application may wish to return {@code null} if it knows that the
     * request being sent can no longer succeed because the existing user ID
     * token or service tokens are no longer valid. This will abort the
     * request. Note that a {@code reauthCode} argument may be provided even if
     * no user authentication data was included in the message.</p>
     * 
     * <p>If the {@code required} parameter is true then user authentication
     * should be returned for this call, even if a user ID token already exists
     * for the user. {@code null} should still be returned when {@code required}
     * is true if the message should be associated with a user but there is no
     * user authentication data. For example during new user creation.</p>
     * 
     * <p>This method will be called multiple times.</p>
     * 
     * @param reauthCode non-{@code null} if new user authentication data is
     *        required. The reason the old user authentication data was
     *        rejected is identified by the code.
     * @param renewable true if the message being sent is renewable.
     * @param required true if user authentication data must be returned.
     * @return the user authentication data or null.
     */
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required);
    
    /**
     * <p>Called if a message does not contain a user ID token for the remote
     * user.</p>
     * 
     * <p>Trusted network clients must always return {@code null}.</p>
     * 
     * <p>If a non-null value is returned by this method and a master token
     * exists for the remote entity then a new user ID token will be created
     * for the remote user and sent in the message. This is not the user
     * identified by {@link #getUserId()} or authenticated by
     * {@link #getUserAuthData(ReauthCode, boolean, boolean)} as those methods
     * are used for the local user.</p>
     * 
     * @return the user to attach to the message or null.
     */
    public MslUser getUser();
    
    /**
     * <p>Called if a request is eligible for key exchange (i.e. the request
     * is renewable and contains entity authentication data or a renewable
     * master token).</p>
     * 
     * <p>Trusted network servers must always return the empty set.</p>
     * 
     * <p>This method must return key request data for all supported key
     * exchange schemes. Failure to provide any key request data may result in
     * message delivery failures.</p>
     * 
     * <p>This method may also be called if entity re-authentication is required
     * for the transaction to complete.</p>
     * 
     * @return the key request data. May be the empty set.
     * @throws MslKeyExchangeException if there is an error generating the key
     *         request data.
     */
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException;
    
    /**
     * <p>Called prior to message sending to allow the processor to modify the
     * message being built.</p>
     * 
     * <p>The boolean {@code handshake} will be true if the function is being
     * called for a handshake message that must be sent before the application
     * data can be sent. The builder for handshake messages may lack a master
     * token, user ID token, and other bound service tokens.</p>
     * 
     * <p>The processor must not attempt to access or retain a reference to the
     * builder after this function completes.</p>
     * 
     * <p>This method will be called multiple times. The set of service tokens
     * managed by the provided message service token builder may be different
     * for each call. The processor should treat each call to this method
     * independently from each other.</p>
     * 
     * @param builder message service token builder.
     * @param handshake true if the provided builder is for a handshake message.
     * @throws MslMessageException if the builder throws an exception or the
     *         desired service tokens cannot be attached.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the service token data.
     * @throws MslEncodingException if there is an error encoding the service
     *         token JSON data.
     * @throws MslException if there is an error compressing the data.
     * @see com.netflix.msl.MslError#RESPONSE_REQUIRES_MASTERTOKEN
     * @see com.netflix.msl.MslError#RESPONSE_REQUIRES_USERIDTOKEN
     */
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslMessageException, MslCryptoException, MslEncodingException, MslException;
    
    /**
     * <p>Called when the message is ready to be sent. The processor should
     * use the provided {@code MessageOutputStream} to write its application
     * data. This method will only be called once.</p>
     * 
     * <p>The processor must not attempt to access or retain a reference to the
     * message output stream after this function completes. It is okay for this
     * method to be long-running as the data will be streamed.</p>
     * 
     * <p>If application data must be sent before the remote entity can reply
     * then this method must call {@link MessageOutputStream#flush()} before
     * returning. If all of the application data must be sent before the remote
     * entity can reply then this method must call
     * {@link MessageOutputStream#close()} before returning. Closing the
     * message output stream will prevent further use of the output stream
     * returned by {@link MslControl}.</p>
     *
     * @param output message output stream.
     * @throws IOException if the output stream throws an I/O exception.
     */
    public void write(final MessageOutputStream output) throws IOException;
    
    /**
     * Returns a message debug context applicable to the message being sent or
     * received.
     * 
     * @return the message debug context or {@code null} if there is none.
     */
    public MessageDebugContext getDebugContext();
}
