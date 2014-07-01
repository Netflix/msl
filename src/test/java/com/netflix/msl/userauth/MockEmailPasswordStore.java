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
package com.netflix.msl.userauth;

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.tokens.MslUser;

/**
 * Test email/password store.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockEmailPasswordStore implements EmailPasswordStore {
    /**
     * A user and password pair.
     */
    private static class UserAndPassword {
        /**
         * Create a new user and password pair.
         * 
         * @param user MSL user.
         * @param password user password.
         */
        public UserAndPassword(final MslUser user, final String password) {
            this.user = user;
            this.password = password;
        }
        
        /** User. */
        private final MslUser user;
        /** User password. */
        private final String password;
    }
    
    /**
     * Add a user to the store.
     * 
     * @param email email address.
     * @param password password.
     * @param user user.
     */
    public void addUser(final String email, final String password, final MslUser user) {
        if (email.trim().isEmpty())
            throw new IllegalArgumentException("Email cannot be blank.");
        if (password.trim().isEmpty())
            throw new IllegalArgumentException("Password cannot be blank.");
        
        final UserAndPassword iap = new UserAndPassword(user, password);
        credentials.put(email, iap);
    }
    
    /**
     * Clear all known users.
     */
    public void clear() {
        credentials.clear();
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.EmailPasswordStore#isUser(java.lang.String, java.lang.String)
     */
    @Override
    public MslUser isUser(final String email, final String password) {
        final UserAndPassword iap = credentials.get(email);
        if (iap == null || !iap.password.equals(password))
            return null;
        return iap.user;
    }

    /** Map of email addresses onto user ID and password pairs. */
    private final Map<String,UserAndPassword> credentials = new HashMap<String,UserAndPassword>();
}
