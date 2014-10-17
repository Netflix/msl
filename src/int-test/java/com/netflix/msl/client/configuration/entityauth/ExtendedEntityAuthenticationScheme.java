package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/29/14
 */
public class ExtendedEntityAuthenticationScheme extends EntityAuthenticationScheme {
    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     *
     * @param name     the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    protected ExtendedEntityAuthenticationScheme(String name, boolean encrypts, boolean protects) {
        super(name, encrypts, protects);
    }
}
