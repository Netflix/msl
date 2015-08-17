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

import com.netflix.msl.tokens.MslUser;

/**
 * An email/password store contains user credentials.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface EmailPasswordStore {
    /**
     * Return the user if the email/password combination is valid.
     * 
     * @param email email address.
     * @param password password.
     * @return the MSL user or null if there is no such user.
     */
    public MslUser isUser(final String email, final String password);
}
