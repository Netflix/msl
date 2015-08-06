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
package server.userauth;

import com.netflix.msl.tokens.MslUser;

/**
 * <p>A MSL user that is just the user ID.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleUser implements MslUser {
    /**
     * <p>Create a new MSL user with the given user ID.</p>
     * 
     * @param userId the user ID.
     */
    public SimpleUser(final String userId) {
        this.userId = userId;
    }
    
    /**
     * @return the user ID.
     */
    public String getUserId() {
        return userId;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.MslUser#getEncoded()
     */
    @Override
    public String getEncoded() {
        return userId;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return userId;
    }

    /** User string representation. */
    private final String userId;
}
