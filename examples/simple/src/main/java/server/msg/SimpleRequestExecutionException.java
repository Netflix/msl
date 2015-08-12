/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
 */
package server.msg;

/**
 * <p>Thrown if an error occurs while executing a request.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleRequestExecutionException extends Exception {
    private static final long serialVersionUID = 1415595607318787406L;

    /**
     * @param message the exception message.
     */
    public SimpleRequestExecutionException(final String message) {
        super(message);
    }
    
    /**
     * @param message the exception message.
     * @param cause the exception cause.
     */
    public SimpleRequestExecutionException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
