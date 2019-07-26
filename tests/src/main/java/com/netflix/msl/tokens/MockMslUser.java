/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.tokens;

/**
 * Test MSL user.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockMslUser implements MslUser {
    /**
     * Create a new MSL user with the specified user ID.
     * 
     * @param id MSL user ID.
     */
    public MockMslUser(final long id) {
        this.id = id;
    }
    
    /**
     * Create a new MSL user from the serialized user data.
     * 
     * @param userdata serialized user data.
     * @throws IllegalArgumentException if the user data is invalid.
     */
    public MockMslUser(final String userdata) {
        try {
            this.id = Long.parseLong(userdata);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid user data serialization: " + userdata, e);
        }
    }
    
    /**
     * @return the user ID.
     */
    public Long getId() {
        return id;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.MslUser#getEncoded()
     */
    @Override
    public String getEncoded() {
        return Long.toString(id);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof MockMslUser)) return false;
        final MockMslUser that = (MockMslUser)obj;
        return this.id == that.id;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return Long.valueOf(id).hashCode();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return Long.toString(id);
    }

    /** User ID. */
    private final long id;
}
