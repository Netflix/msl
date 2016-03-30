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

import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * Thrown when there is a problem with a master token, but the token was
 * successfully parsed.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslMasterTokenException extends MslException {
    private static final long serialVersionUID = -3151662441952286016L;

    /**
     * Construct a new MSL master token exception with the specified error and
     * master token.
     *
     * @param error the error.
     * @param masterToken the master token. May be null.
     */
    public MslMasterTokenException(final MslError error, final MasterToken masterToken) {
        super(error);
        setMasterToken(masterToken);
    }

    /**
     * Construct a new MSL master token exception with the specified error and
     * master token.
     *
     * @param error the error.
     * @param masterToken the master token. May be null.
     * @param cause the exception that triggered this exception being thrown
     */
    public MslMasterTokenException(final MslError error, final MasterToken masterToken, final Throwable cause) {
        super(error, cause);
        setMasterToken(masterToken);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setUserIdToken(com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslMasterTokenException setUserIdToken(final UserIdToken userIdToken) {
        super.setUserIdToken(userIdToken);
        return this;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setUserAuthenticationData(com.netflix.msl.userauth.UserAuthenticationData)
     */
    @Override
    public MslMasterTokenException setUserAuthenticationData(final UserAuthenticationData userAuthData) {
        super.setUserAuthenticationData(userAuthData);
        return this;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.MslException#setMessageId(long)
     */
    @Override
    public MslMasterTokenException setMessageId(final long messageId) {
        super.setMessageId(messageId);
        return this;
    }
}
