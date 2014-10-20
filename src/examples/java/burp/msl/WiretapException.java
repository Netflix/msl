/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
 */
package burp.msl;

/**
 * <p>Thrown when a wiretap exception occurs.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class WiretapException extends Exception {
    private static final long serialVersionUID = 664626450364720991L;

    /**
     * <p>Create a new wiretap exception with the provided message.</p>
     * 
     * @param message the detail message.
     */
    public WiretapException(final String message) {
        super(message);
        // TODO Auto-generated constructor stub
    }

    /**
     * <p>Create a new wiretap exception with the provided message and
     * cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public WiretapException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
