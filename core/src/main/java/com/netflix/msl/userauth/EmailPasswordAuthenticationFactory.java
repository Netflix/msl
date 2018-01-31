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
package com.netflix.msl.userauth;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * Email/password-based user authentication factory.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EmailPasswordAuthenticationFactory extends UserAuthenticationFactory {
    /**
     * Construct a new email/password-based user authentication factory.
     *
     * @param store email/password store.
     * @param authutils authentication utilities.
     */
    public EmailPasswordAuthenticationFactory(final EmailPasswordStore store, final AuthenticationUtils authutils) {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
        this.store = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    public UserAuthenticationData createData(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslEncodingException {
        return new EmailPasswordAuthenticationData(userAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, final UserIdToken userIdToken) throws MslUserAuthException {
        // Make sure we have the right kind of user authentication data.
        if (!(data instanceof EmailPasswordAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + data.getClass().getName() + ".");
        final EmailPasswordAuthenticationData epad = (EmailPasswordAuthenticationData)data;

        // Verify the scheme is permitted.
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslUserAuthException(MslError.USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " + this.getScheme() + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

        // Extract and check email and password values.
        final String epadEmail = epad.getEmail();
        final String epadPassword = epad.getPassword();
        if (epadEmail == null || epadPassword == null)
            throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
        final String email = epadEmail.trim();
        final String password = epadPassword.trim();
        if (email.isEmpty() || password.isEmpty())
            throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);

        // Authenticate the user.
        final MslUser user = store.isUser(email, password);
        if (user == null)
            throw new MslUserAuthException(MslError.EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);
        
        // Verify the scheme is still permitted.
        if (!authutils.isSchemePermitted(identity, user, this.getScheme()))
            throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.getScheme() + " not permitted for entity " + identity + ".").setUserAuthenticationData(epad);
        
        // If a user ID token was provided validate the user identities.
        if (userIdToken != null) {
            final MslUser uitUser = userIdToken.getUser();
            if (!user.equals(uitUser))
                throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser).setUserAuthenticationData(epad);
        }
        
        // Return the user.
        return user;
    }

    /** Email/password store. */
    private final EmailPasswordStore store;
    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}
