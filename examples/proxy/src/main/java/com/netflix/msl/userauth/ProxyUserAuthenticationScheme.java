/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.userauth;

import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>Proxy user authentication schemes.</p>
 * 
 * <p>All user authentication schemes are automatically re-mapped onto the
 * proxy key exchange scheme.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyUserAuthenticationScheme extends UserAuthenticationScheme {
    /** Proxy key exchange scheme. */
    public static final UserAuthenticationScheme PROXY = new ProxyUserAuthenticationScheme("PROXY");

    /**
     * Define a user authentication scheme with the specified name.
     * 
     * @param name the user authentication scheme name.
     */
    public ProxyUserAuthenticationScheme(final String name) {
        super(name);
    }
}
