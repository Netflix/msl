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
package com.netflix.msl.entityauth;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Entity authentication schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify entity authentication
 * schemes.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EntityAuthenticationScheme {
    /** Map of names onto schemes. */
    private static Map<String,EntityAuthenticationScheme> schemes = new HashMap<String,EntityAuthenticationScheme>();
    
    /** Pre-shared keys. */
    public static final EntityAuthenticationScheme PSK = new EntityAuthenticationScheme("PSK", true, true);
    /** Pre-shared keys with entity profiles. */
    public static final EntityAuthenticationScheme PSK_PROFILE = new EntityAuthenticationScheme("PSK_PROFILE", true, true);
    /** X.509 public/private key pair. */
    public static final EntityAuthenticationScheme X509 = new EntityAuthenticationScheme("X509", false, true);
    /** RSA public/private key pair. */
    public static final EntityAuthenticationScheme RSA = new EntityAuthenticationScheme("RSA", false, true);
    /** ECC public/private key pair. */
    public static final EntityAuthenticationScheme ECC = new EntityAuthenticationScheme("ECC", false, true);
    /** Unauthenticated. */
    public static final EntityAuthenticationScheme NONE = new EntityAuthenticationScheme("NONE", false, false);
    /** Unauthenticated suffixed. */
    public static final EntityAuthenticationScheme NONE_SUFFIXED = new EntityAuthenticationScheme("NONE_SUFFIXED", false, false);
    /** Master token protected. */
    public static final EntityAuthenticationScheme MT_PROTECTED = new EntityAuthenticationScheme("MT_PROTECTED", false, false);
    /** Provisioned. */
    public static final EntityAuthenticationScheme PROVISIONED = new EntityAuthenticationScheme("PROVISIONED", false, false);
    
    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     * 
     * @param name the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    protected EntityAuthenticationScheme(final String name, final boolean encrypts, final boolean protects) {
        this.name = name;
        this.encrypts = encrypts;
        this.protects = protects;
        
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
    public static EntityAuthenticationScheme getScheme(final String name) {
        return schemes.get(name);
    }
    
    /**
     * @return all known entity authentication schemes.
     */
    public static Collection<EntityAuthenticationScheme> values() {
        return schemes.values();
    }
    
    /**
     * @return the scheme identifier.
     */
    public String name() {
        return name;
    }
    
    /**
     * @return true if the scheme encrypts message data.
     */
    public boolean encrypts() {
        return encrypts;
    }
    
    /**
     * @return true if the scheme protects message integrity.
     */
    public boolean protectsIntegrity() {
        return protects;
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
        if (!(obj instanceof EntityAuthenticationScheme)) return false;
        final EntityAuthenticationScheme that = (EntityAuthenticationScheme)obj;
        return this.name.equals(that.name);
    }

    /** Scheme name. */
    private final String name;
    /** Encrypts message data. */
    private final boolean encrypts;
    /** Protects message integrity. */
    private final boolean protects;
}
