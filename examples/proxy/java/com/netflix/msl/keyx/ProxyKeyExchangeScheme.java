/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.keyx;

import com.netflix.msl.keyx.KeyExchangeScheme;

/**
 * <p>Proxy key exchange schemes.</p>
 * 
 * <p>All key exchange schemes are automatically re-mapped onto the proxy
 * key exchange scheme.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyKeyExchangeScheme extends KeyExchangeScheme {
    /** Proxy key exchange scheme. */
    public static final KeyExchangeScheme PROXY = new ProxyKeyExchangeScheme("PROXY");

    /**
     * Define a key exchange scheme with the specified name.
     * 
     * @param name the key exchange scheme name.
     */
    public ProxyKeyExchangeScheme(final String name) {
        super(name);
    }
}
