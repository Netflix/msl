/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

/**
 * <p>Thrown when there is a communication failure with the external MSL
 * service being proxed.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyIoException extends ProxyException {
    private static final long serialVersionUID = 999987202864141531L;

    /**
     * <p>Creates a new {@code ProxyIOException} with the specified detail
     * message and cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public ProxyIoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
