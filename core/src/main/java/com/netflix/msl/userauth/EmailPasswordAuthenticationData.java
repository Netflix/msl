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
package com.netflix.msl.userauth;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;

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
@EqualsAndHashCode(callSuper = true)
@Getter
public class EmailPasswordAuthenticationData extends UserAuthenticationData {
    /** JSON email key. */
    private static final String KEY_EMAIL = "email";
    /** JSON password key. */
    private static final String KEY_PASSWORD = "password";

    /** Email. */
    private final String email;
    /** Password. */
    private final String password;

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
     * provided JSON representation.
     * 
     * @param emailPasswordAuthJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    public EmailPasswordAuthenticationData(final JSONObject emailPasswordAuthJO) throws MslEncodingException {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
        try {
            email = emailPasswordAuthJO.getString(KEY_EMAIL);
            password = emailPasswordAuthJO.getString(KEY_PASSWORD);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "email/password authdata " + emailPasswordAuthJO.toString(), e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#getCredentials()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_EMAIL, email);
            jsonObj.put(KEY_PASSWORD, password);
            return jsonObj;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "email/password authdata", e);
        }
    }

}
