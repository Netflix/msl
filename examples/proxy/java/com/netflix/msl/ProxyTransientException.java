/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

/**
 * <p>Thrown when there is a transient failure indicating the operation may
 * succeed at a later time.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyTransientException extends ProxyException {
    private static final long serialVersionUID = -99248671046579868L;

    /**
     * <p>Creates a new {@code ProxyTransientException} with the specified detail
     * message and cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public ProxyTransientException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
