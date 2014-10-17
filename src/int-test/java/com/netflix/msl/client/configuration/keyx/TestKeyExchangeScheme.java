package com.netflix.msl.client.configuration.keyx;

import com.netflix.msl.keyx.KeyExchangeScheme;

/**
 * User: skommidi
 * Date: 9/2/14
 */
public class TestKeyExchangeScheme extends KeyExchangeScheme {

    public static final KeyExchangeScheme NULL_KEYX_SCHEME = new TestKeyExchangeScheme("NULL_KEYX_SCHEME");

    /**
     * Define a key exchange scheme with the specified name.
     *
     * @param name the key exchange scheme name.
     */
    protected TestKeyExchangeScheme(String name) {
        super(name);
    }
}
