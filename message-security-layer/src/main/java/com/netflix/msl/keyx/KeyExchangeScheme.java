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
package com.netflix.msl.keyx;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Key exchange schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify key exchange schemes.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KeyExchangeScheme {
    /** Map of names onto schemes. */
    private static Map<String,KeyExchangeScheme> schemes = new HashMap<String,KeyExchangeScheme>();
    
    /** Asymmetric key wrapped. */
    public static final KeyExchangeScheme ASYMMETRIC_WRAPPED = new KeyExchangeScheme("ASYMMETRIC_WRAPPED");
    /** Diffie-Hellman exchange (Netflix SHA-384 key derivation). */
    public static final KeyExchangeScheme DIFFIE_HELLMAN = new KeyExchangeScheme("DIFFIE_HELLMAN");
    /** JSON web encryption ladder exchange. */
    public static final KeyExchangeScheme JWE_LADDER = new KeyExchangeScheme("JWE_LADDER");
    /** JSON web key ladder exchange. */
    public static final KeyExchangeScheme JWK_LADDER = new KeyExchangeScheme("JWK_LADDER");
    /** Symmetric key wrapped. */
    public static final KeyExchangeScheme SYMMETRIC_WRAPPED = new KeyExchangeScheme("SYMMETRIC_WRAPPED");
    
    /**
     * Define a key exchange scheme with the specified name.
     * 
     * @param name the key exchange scheme name.
     */
    protected KeyExchangeScheme(final String name) {
        this.name = name;
        
        // Add this scheme to the map.
        synchronized (schemes) {
            schemes.put(name, this);
        }
    }
    
    /**
     * @param name the key exchange scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    public static KeyExchangeScheme getScheme(final String name) {
        return schemes.get(name);
    }
    
    /**
     * @return all known key exchange schemes.
     */
    public static Collection<KeyExchangeScheme> values() {
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
        if (!(obj instanceof KeyExchangeScheme)) return false;
        final KeyExchangeScheme that = (KeyExchangeScheme)obj;
        return this.name.equals(that.name);
    }
    
    /** Scheme name. */
    private final String name;
}
