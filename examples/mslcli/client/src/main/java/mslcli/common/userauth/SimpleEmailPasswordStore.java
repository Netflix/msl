/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

package mslcli.common.userauth;

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.EmailPasswordStore;

import mslcli.common.tokens.SimpleUser;
import mslcli.common.util.SharedUtil;

/**
 * <p>Memory-backed user email/password store.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleEmailPasswordStore implements EmailPasswordStore {
    /**
     * <p>Create a new email/password store that will authenticate the provided
     * users.</p>
     * 
     * @param emailPasswords map of email addresses onto passwords.
     */
    public SimpleEmailPasswordStore(final Map<String,String> emailPasswords) {
        if (emailPasswords == null) {
            throw new IllegalArgumentException("NULL emal-password map");
        }
        this.emailPasswords.putAll(emailPasswords);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.EmailPasswordStore#isUser(java.lang.String, java.lang.String)
     */
    @Override
    public MslUser isUser(final String email, final String password) {
        final String expectedPassword = emailPasswords.get(email);
        if (expectedPassword == null || !expectedPassword.equals(password))
            return null;
        return new SimpleUser(email);
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }

    /** Email/password database. */
    private final Map<String,String> emailPasswords = new HashMap<String,String>();
}
