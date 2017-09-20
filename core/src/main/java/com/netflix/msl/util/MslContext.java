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
package com.netflix.msl.util;

import java.util.Date;
import java.util.Random;
import java.util.SortedSet;

import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>The context provides access to all factories, builders, and containers
 * that are needed by the MSL library. There is expected to be one global
 * context per trusted services network or peer-to-peer network. By extension,
 * the MSL store instance returned by the context is expected to be specific to
 * the owning context.</p>
 * 
 * @see MslStore
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class MslContext {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Re-authentication reason codes. */
    public static enum ReauthCode {
        /** The master token was rejected as bad or invalid. */
        ENTITY_REAUTH(ResponseCode.ENTITY_REAUTH),
        /** The entity authentication data failed to authenticate the entity. */
        ENTITYDATA_REAUTH(ResponseCode.ENTITYDATA_REAUTH),
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
     * Returns the local entity time. This is assumed to be the real time.
     * 
     * @return {number} the local entity time in milliseconds since the epoch.
     */
    public abstract long getTime();
    
    /**
     * <p>Returns a random number generator.</p>
     * 
     * <p>It is extremely important to provide a secure (pseudo-)random number
     * generator with a good source of entropy. Many random number generators,
     * including those found in the Java Runtime Environment, JavaScript, and
     * operating systems do not provide sufficient randomness.</p>
     * 
     * <p>If in doubt, performing an {@code XOR} on the output of two or more
     * independent random sources can be used to provide better random
     * values.</p>
     * 
     * @return a random number generator.
     */
    public abstract Random getRandom();
    
    /**
     * Returns true if the context is operating in a peer-to-peer network. The
     * message processing logic is slightly different in peer-to-peer networks.
     * 
     * @return true if in peer-to-peer mode.
     */
    public abstract boolean isPeerToPeer();
    
    /**
     * Returns the message capabilities for this entity.
     * 
     * @return this entity's message capabilities.
     */
    public abstract MessageCapabilities getMessageCapabilities();
    
    /**
     * <p>Returns the entity authentication data for this entity. This is used
     * to authenticate messages prior to generation of a master token.</p>
     * 
     * <p>This method should never return {@code null} but may do so in the one
     * situation when the {@code reauthCode} parameter is provided and the
     * application knows that the request being sent can no longer succeed
     * because the existing master token, user ID token, or service tokens are
     * no longer valid. This will abort the request.</p>
     * 
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITY_REAUTH} then the existing master token has been
     * rejected, along with its bound user ID tokens and service tokens.</p>
     * 
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITYDATA_REAUTH} then new entity re-authentication
     * data should be returned for this and all subsequent calls.</p>
     * 
     * <p>The entity authentication scheme must never change.</p>
     * 
     * <p>This method will be called multiple times.</p>
     * 
     * @param reauthCode non-{@code null} if the master token or entity
     *        authentication data was rejected. If the entity authentication
     *        data was rejected then new entity authentication data is
     *        required.
     * @return this entity's entity authentication data or null.
     */
    public abstract EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode);
    
    /**
     * <p>Returns the primary crypto context used for MSL-level crypto
     * operations. This is used for the master tokens and user ID tokens.</p>
     * 
     * <p>Trusted network clients should return a crypto context that always
     * returns false for verification. The other crypto context methods will
     * not be used by trusted network clients.</p>
     * 
     * @return the primary MSL crypto context.
     * @throws MslCryptoException if there is an error creating the crypto
     *         context.
     */
    public abstract ICryptoContext getMslCryptoContext() throws MslCryptoException;
    
    /**
     * <p>Returns the entity authentication scheme identified by the specified
     * name or {@code null} if there is none.</p>
     * 
     * @param name the entity authentication scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    public abstract EntityAuthenticationScheme getEntityAuthenticationScheme(final String name);

    /**
     * Returns the entity authentication factory for the specified scheme.
     * 
     * @param scheme the entity authentication scheme.
     * @return the entity authentication factory, or null if no factory is
     *         available.
     */
    public abstract EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme);

    /**
     * <p>Returns the user authentication scheme identified by the specified
     * name or {@code null} if there is none.</p>
     * 
     * @param name the user authentication scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    public abstract UserAuthenticationScheme getUserAuthenticationScheme(final String name);

    /**
     * Returns the user authentication factory for the specified scheme.
     * 
     * Trusted network clients should always return null.
     * 
     * @param scheme the user authentication scheme.
     * @return the user authentication factory, or null if no factory is
     *         available.
     */
    public abstract UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme);
    
    /**
     * Returns the token factory.
     * 
     * This method will not be called by trusted network clients.
     * 
     * @return the token factory.
     */
    public abstract TokenFactory getTokenFactory();

    /**
     * <p>Returns the key exchange scheme identified by the specified name or
     * {@code null} if there is none.</p>
     * 
     * @param name the key exchange scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    public abstract KeyExchangeScheme getKeyExchangeScheme(final String name);

    /**
     * Returns the key exchange factory for the specified scheme.
     * 
     * @param scheme the key exchange scheme.
     * @return the key exchange factory, or null if no factory is available.
     */
    public abstract KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme);
    
    /**
     * Returns the supported key exchange factories in order of preferred use.
     * This should return an immutable collection.
     * 
     * @return the key exchange factories, or the empty set.
     */
    public abstract SortedSet<KeyExchangeFactory> getKeyExchangeFactories();
    
    /**
     * Returns the MSL store specific to this MSL context.
     * 
     * @return the MSL store.
     */
    public abstract MslStore getMslStore();
    
    /**
     * Returns the MSL encoder factory specific to this MSL context.
     * 
     * @return the MSL encoder factory.
     */
    public abstract MslEncoderFactory getMslEncoderFactory();

    /**
     * <p>Update the remote entity time.</p>
     * 
     * <p>This function is only used by {@link MslControl} and should not be
     * used by the application.</p>
     * 
     * @param time remote entity time.
     */
    public final void updateRemoteTime(final Date time) {
        final long localSeconds = getTime() / MILLISECONDS_PER_SECOND;
        final long remoteSeconds = time.getTime() / MILLISECONDS_PER_SECOND;
        offset = remoteSeconds - localSeconds;
        synced = true;
    }

    /**
     * <p>Return the expected remote entity time or {@code null} if the clock
     * is not yet synchronized.</p>
     * 
     * <p>This function is only used by {@link MslControl} and should not be
     * used by the application.</p>
     * 
     * @return the expected remote entity time or {@code null} if not known.
     */
    public final Date getRemoteTime() {
        if (!synced) return null;
        final long localSeconds = getTime() / MILLISECONDS_PER_SECOND;
        final long remoteSeconds = localSeconds + offset;
        return new Date(remoteSeconds * MILLISECONDS_PER_SECOND);
    }
    
    /** Remote clock is synchronized. */
    private volatile boolean synced = false;
    /** Remote entity time offset from local time in seconds. */
    private volatile long offset = 0;
}
