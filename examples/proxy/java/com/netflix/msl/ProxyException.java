/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

/**
 * <p>Thrown by the proxy when an exception has occurred. This class is the
 * general class of exceptions produced by failed proxy operations.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyException extends Exception {
    private static final long serialVersionUID = -2504349809538822945L;

    /**
     * <p>Creates a new {@code ProxyException} with the specified detail
     * message and cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public ProxyException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
