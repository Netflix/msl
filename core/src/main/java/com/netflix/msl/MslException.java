/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl;

import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * Thrown when an exception occurs within the Message Security Layer.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslException extends Exception {
    private static final long serialVersionUID = -2444322310603180494L;

    /**
     * Construct a new MSL exception with the specified error.
     * 
     * @param error the error.
     */
    public MslException(final MslError error) {
        super(error.getMessage());
        this.error = error;
    }
    
    /**
     * Construct a new MSL exception with the specified error and details.
     * 
     * @param error the error.
     * @param details the details text.
     */
    public MslException(final MslError error, final String details) {
        super(error.getMessage() + " [" + details + "]");
        this.error = error;
    }
    
    
    /**
     * Construct a new MSL exception with the specified error, details, and
     * cause.
     * 
     * @param error the error.
     * @param details the details text.
     * @param cause the cause.
     */
    public MslException(final MslError error, final String details, final Throwable cause) {
        super(error.getMessage() + " [" + details + "]", cause);
        this.error = error;
    }
    
    /**
     * Construct a new MSL exception with the specified error and cause.
     * 
     * @param error the error.
     * @param cause the cause.
     */
    public MslException(final MslError error, final Throwable cause) {
        super(error.getMessage(), cause);
        this.error = error;
    }
    
    /**
     * Set the entity associated with the exception, using a master token. This
     * does nothing if the entity is already set.
     * 
     * @param masterToken entity associated with the error. May be null.
     * @return this.
     */
    public MslException setMasterToken(final MasterToken masterToken) {
        if (getMasterToken() == null && getEntityAuthenticationData() == null)
            this.masterToken = masterToken;
        return this;
    }
    
    /**
     * Set the entity associated with the exception, using entity
     * authentication data. This does nothing if the entity is already set.
     * 
     * @param entityAuthData entity associated with the error. May be null.
     * @return this.
     */
    public MslException setEntityAuthenticationData(final EntityAuthenticationData entityAuthData) {
        if (getMasterToken() == null && getEntityAuthenticationData() == null)
            this.entityAuthData = entityAuthData;
        return this;
    }
    
    /**
     * Set the user associated with the exception, using a user ID token. This
     * does nothing if the user is already set.
     * 
     * @param userIdToken user associated with the error. May be null.
     * @return this.
     */
    public MslException setUserIdToken(final UserIdToken userIdToken) {
        if (getUserIdToken() == null && getUserAuthenticationData() == null)
            this.userIdToken = userIdToken;
        return this;
    }
    
    /**
     * Set the user associated with the exception, using user authentication
     * data. This does nothing if the user is already set.
     * 
     * @param userAuthData user associated with the error. May be null.
     * @return this.
     */
    public MslException setUserAuthenticationData(final UserAuthenticationData userAuthData) {
        if (getUserIdToken() == null && getUserAuthenticationData() == null)
            this.userAuthData = userAuthData;
        return this;
    }
    
    /**
     * Set the message ID of the message associated with the exception. This
     * does nothing if the message ID is already set.
     * 
     * @param messageId message ID of the message associated with this error.
     * @return this.
     */
    public MslException setMessageId(final long messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new IllegalArgumentException("Message ID " + messageId + " is outside the valid range.");
        if (getMessageId() == null)
            this.messageId = Long.valueOf(messageId);
        return this;
    }
    
    /**
     * @return the error.
     */
    public MslError getError() {
        return error;
    }
    
    /**
     * Returns the master token of the entity associated with the exception.
     * May be null if the entity is identified by entity authentication data or
     * not applicable to the exception.
     * 
     * @return the master token or null.
     * @see #getEntityAuthenticationData()
     */
    public MasterToken getMasterToken() {
        if (masterToken != null)
            return masterToken;
        
        // We have to search through the stack in case there is a nested master
        // token.
        final Throwable cause = getCause();
        if (cause != null && cause instanceof MslException) {
            final MslException mslCause = (MslException)cause;
            return mslCause.getMasterToken();
        }
        
        // No master token.
        return null;
    }

    /**
     * Returns the entity authentication data of the entity associated with the
     * exception. May be null if the entity is identified by a master token or
     * not applicable to the exception.
     * 
     * @return the entity authentication data or null.
     * @see #getMasterToken()
     */
    public EntityAuthenticationData getEntityAuthenticationData() {
        if (entityAuthData != null)
            return entityAuthData;
        
        // We have to search through the stack in case there is a nested entity
        // authentication data.
        final Throwable cause = getCause();
        if (cause != null && cause instanceof MslException) {
            final MslException mslCause = (MslException)cause;
            return mslCause.getEntityAuthenticationData();
        }
        
        // No entity authentication data.
        return null;
    }
    
    /**
     * Returns the user ID token of the user associated with the exception. May
     * be null if the user is identified by user authentication data or not
     * applicable to the exception.
     * 
     * @return the user ID token or null.
     * @see #getUserAuthenticationData()
     */
    public UserIdToken getUserIdToken() {
        if (userIdToken != null)
            return userIdToken;
        
        // We have to search through the stack in case there is a nested user
        // ID token.
        final Throwable cause = getCause();
        if (cause != null && cause instanceof MslException) {
            final MslException mslCause = (MslException)cause;
            return mslCause.getUserIdToken();
        }
        
        // No user ID token.
        return null;
    }
    
    /**
     * Returns the user authentication data of the user associated with the
     * exception. May be null if the user is identified by a user ID token or
     * not applicable to the exception.
     * 
     * @return the user authentication data or null.
     * @see #getUserIdToken()
     */
    public UserAuthenticationData getUserAuthenticationData() {
        if (userAuthData != null)
            return userAuthData;
        
        // We have to search through the stack in case there is a nested user
        // authentication data.
        final Throwable cause = getCause();
        if (cause != null && cause instanceof MslException) {
            final MslException mslCause = (MslException)cause;
            return mslCause.getUserAuthenticationData();
        }
        
        // No user authentication data.
        return null;
    }
    
    /**
     * Returns the message ID of the message associated with the exception. May
     * be null if there is no message associated or the exception was thrown
     * before extracting the message ID.
     * 
     * @return the message ID or null.
     */
    public Long getMessageId() {
        if (messageId != null)
            return messageId;
        
        // We have to search through the stack in case there is a nested
        // message ID.
        final Throwable cause = getCause();
        if (cause != null && cause instanceof MslException) {
            final MslException mslCause = (MslException)cause;
            return mslCause.getMessageId();
        }
        
        // No message ID.
        return null;
    }
    
    /** MSL error. */
    private final MslError error;
    /** Master token. */
    private MasterToken masterToken = null;
    /** Entity authentication data. */
    private EntityAuthenticationData entityAuthData = null;
    /** User ID token. */
    private UserIdToken userIdToken = null;
    /** User authentication data. */
    private UserAuthenticationData userAuthData = null;
    /** Message ID. */
    private Long messageId = null;
}
