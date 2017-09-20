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
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>Email/password-based user authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "email", "password" ],
 *   "email" : "string",
 *   "password" : "string"
 * }} where:
 * <ul>
 * <li>{@code email} is the user email address</li>
 * <li>{@code password} is the user password</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EmailPasswordAuthenticationData extends UserAuthenticationData {
    /** Key email. */
    private static final String KEY_EMAIL = "email";
    /** Key password. */
    private static final String KEY_PASSWORD = "password";
    
    /**
     * Construct a new email/password authentication data instance from the
     * specified email and password.
     * 
     * @param email the email address.
     * @param password the password.
     */
    public EmailPasswordAuthenticationData(final String email, final String password) {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
        this.email = email;
        this.password = password;
    }

    /**
     * Construct a new email/password authentication data instance from the
     * provided MSL object.
     * 
     * @param emailPasswordAuthMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    public EmailPasswordAuthenticationData(final MslObject emailPasswordAuthMo) throws MslEncodingException {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
        try {
            email = emailPasswordAuthMo.getString(KEY_EMAIL);
            password = emailPasswordAuthMo.getString(KEY_PASSWORD);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "email/password authdata " + emailPasswordAuthMo, e);
        }
    }
    
    /**
     * @return the email address.
     */
    public String getEmail() {
        return email;
    }
    
    /**
     * @return the password.
     */
    public String getPassword() {
        return password;
    }

    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_EMAIL, email);
        mo.put(KEY_PASSWORD, password);
        return mo;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof EmailPasswordAuthenticationData)) return false;
        final EmailPasswordAuthenticationData that = (EmailPasswordAuthenticationData)obj;
        return super.equals(obj) && email.equals(that.email) && password.equals(that.password);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ email.hashCode() ^ password.hashCode();
    }

    /** Email. */
    private final String email;
    /** Password. */
    private final String password;
}
