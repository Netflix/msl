/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.entityauth;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;

/**
 * <p>Proxy entity authentication schemes.</p>
 * 
 * <p>All entity authentication schemes are automatically re-mapped onto the
 * proxy entity authentication scheme.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyEntityAuthenticationScheme extends EntityAuthenticationScheme {
    /** Proxy entity authentication scheme. */
    public static final EntityAuthenticationScheme PROXY = new ProxyEntityAuthenticationScheme("PROXY", false, false);

    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     * 
     * @param name the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    protected ProxyEntityAuthenticationScheme(String name, boolean encrypts, boolean protects) {
        super(name, encrypts, protects);
    }
}
