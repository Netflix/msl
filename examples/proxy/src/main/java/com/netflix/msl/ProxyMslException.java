/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

/**
 * <p>Thrown by the proxy when a MSL exception has occurred.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyMslException extends ProxyException {
    private static final long serialVersionUID = 2621303915896379638L;

    /**
     * <p>Creates a new {@code ProxyMslException} with the specified detail
     * message and cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public ProxyMslException(final String message, final MslException cause) {
        super(message, cause);
    }
}
