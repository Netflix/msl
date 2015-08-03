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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>User authentication schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify user authentication
 * schemes.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserAuthenticationScheme {
    /** Map of names onto schemes. */
    private static Map<String,UserAuthenticationScheme> schemes = new HashMap<String,UserAuthenticationScheme>();
    
    /** Email/password. */
    public static final UserAuthenticationScheme EMAIL_PASSWORD = new UserAuthenticationScheme("EMAIL_PASSWORD");
    /** User ID token. */
    public static final UserAuthenticationScheme USER_ID_TOKEN = new UserAuthenticationScheme("USER_ID_TOKEN");
    
    /**
     * Define a user authentication scheme with the specified name.
     * 
     * @param name the user authentication scheme name.
     */
    protected UserAuthenticationScheme(final String name) {
        this.name = name;
        
        // Add this scheme to the map.
        synchronized (schemes) {
            schemes.put(name, this);
        }
    }
    
    /**
     * @param name the entity authentication scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    public static UserAuthenticationScheme getScheme(final String name) {
        return schemes.get(name);
    }
    
    /**
     * @return all known user authentication schemes.
     */
    public static Collection<UserAuthenticationScheme> values() {
        return schemes.values();
    }
    
    /**
     * @return the scheme identifier.
     */
    public String name() {
        return name;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return name();
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return name.hashCode();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof UserAuthenticationScheme)) return false;
        final UserAuthenticationScheme that = (UserAuthenticationScheme)obj;
        return this.name.equals(that.name);
    }
    
    /** Scheme name. */
    private final String name;
}
