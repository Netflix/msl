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
package com.netflix.msl.userauth;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockMslUser;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * Test email/password authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockEmailPasswordAuthenticationFactory extends UserAuthenticationFactory {
    /** Email. */
    public static final String EMAIL = "email1@domain.com";
    /** Password. */
    public static final String PASSWORD = "password";
    /** User. */
    public static final MslUser USER = new MockMslUser(312204600);
    
    /** Email #2. */
    public static final String EMAIL_2 = "email2@domain.com";
    /** Password #2. */
    public static final String PASSWORD_2 = "password2";
    /** User #2. */
    public static final MslUser USER_2 = new MockMslUser(880083944);

    /**
     * Create a new test email/password authentication factory.
     */
    public MockEmailPasswordAuthenticationFactory() {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    public UserAuthenticationData createData(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslEncodingException {
        return new EmailPasswordAuthenticationData(userAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.EmailPasswordAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, final UserIdToken userIdToken) throws MslUserAuthException {
        // Make sure we have the right kind of user authentication data.
        if (!(data instanceof EmailPasswordAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + data.getClass().getName() + ".");
        final EmailPasswordAuthenticationData epad = (EmailPasswordAuthenticationData)data;

        // Extract and check email and password values.
        final String epadEmail = epad.getEmail();
        final String epadPassword = epad.getPassword();
        if (epadEmail == null || epadPassword == null)
            throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
        final String email = epadEmail.trim();
        final String password = epadPassword.trim();
        if (email.isEmpty() || password.isEmpty())
            throw new MslUserAuthException(MslError.EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
        
        // Identify the user.
        final MslUser user;
        if (EMAIL.equals(email) && PASSWORD.equals(password))
            user = USER;
        else if (EMAIL_2.equals(email) && PASSWORD_2.equals(password))
            user = USER_2;
        else
            throw new MslUserAuthException(MslError.EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);

        // If a user ID token was provided validate the user identities.
        if (userIdToken != null) {
            final MslUser uitUser = userIdToken.getUser();
            if (!user.equals(uitUser))
                throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser);
        }
        
        // Return the user.
        return user;
    }
}
