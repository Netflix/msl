/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

/**
 * Thrown when there is a problem with a user ID token, but the token was
 * successfully parsed.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslUserIdTokenException extends MslException {
    private static final long serialVersionUID = 8796880393236563071L;

    /**
     * Construct a new MSL user ID token exception with the specified error and
     * user ID token.
     *
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     */
    public MslUserIdTokenException(final MslError error, final UserIdToken userIdToken) {
        super(error);
        setUserIdToken(userIdToken);
    }
    
    /**
     * Construct a new MSL user ID token exception with the specified error,
     * user ID token, and details.
     * 
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     * @param details the details text.
     */
    public MslUserIdTokenException(final MslError error, final UserIdToken userIdToken, final String details) {
        super(error, details);
        setUserIdToken(userIdToken);
    }
    
    /**
     * Construct a new MSL user ID token exception with the specified error,
     * user ID token, details, and cause.
     * 
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     * @param details the details text.
     * @param cause the cause.
     */
    public MslUserIdTokenException(final MslError error, final UserIdToken userIdToken, final String details, final Throwable cause) {
        super(error, details, cause);
        setUserIdToken(userIdToken);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setMasterToken(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslUserIdTokenException setMasterToken(final MasterToken masterToken) {
        super.setMasterToken(masterToken);
        return this;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setEntityAuthenticationData(com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public MslUserIdTokenException setEntityAuthenticationData(final EntityAuthenticationData entityAuthData) {
        super.setEntityAuthenticationData(entityAuthData);
        return this;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setMessageId(long)
     */
    @Override
    public MslUserIdTokenException setMessageId(final long messageId) {
        super.setMessageId(messageId);
        return this;
    }
}
