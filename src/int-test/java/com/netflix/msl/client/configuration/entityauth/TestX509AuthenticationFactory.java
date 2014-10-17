package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.entityauth.MockX509AuthenticationFactory;

/**
 * User: skommidi
 * Date: 7/29/14
 */
public class TestX509AuthenticationFactory extends MockX509AuthenticationFactory {

    /** X.509 private key. */
    private static final String X509_PRIVATE_KEY = "entityauth/expired.key";
    /** X.509 self-signed resource certificate. */
    private static final String X509_SELF_SIGNED_CERT = "entityauth/expired.pem";

}
