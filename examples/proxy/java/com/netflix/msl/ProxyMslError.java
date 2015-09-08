/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

import com.netflix.msl.MslConstants.ResponseCode;

/**
 * <p>Proxy MSL error codes and descriptions.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyMslError extends MslError {
    /** Zuul proxy internal error code offset value. */
    private static final int OFFSET = 200000;
    
    // 1 Master Token
    public static final MslError MASTERTOKEN_CREATION_REQUIRED = new ProxyMslError(1000, ResponseCode.FAIL, "Master token creation required.", true);
    public static final MslError MASTERTOKEN_RENEWAL_REQUIRED = new ProxyMslError(1001, ResponseCode.FAIL, "Master token renewal required.", true);
    
    // 2 User ID Token
    public static final MslError USERIDTOKEN_CREATION_REQUIRED = new ProxyMslError(2000, ResponseCode.FAIL, "User ID token creation required.", true);
    public static final MslError USERIDTOKEN_RENEWAL_REQUIRED = new ProxyMslError(2001, ResponseCode.FAIL, "User ID token renewal required.", true);
    
    // 3 Service Token
    
    // 4 Entity Authentication
    public static final MslError ENTITYAUTH_REQUIRED = new ProxyMslError(4000, ResponseCode.FAIL, "Entity authentication required.", true);
    public static final MslError ENTITYAUTH_CANNOT_FAILOVER = new ProxyMslError(4001, ResponseCode.TRANSIENT_FAILURE, "Entity authentication cannot be handled during failover.", false);
    
    // 5 User Authentication
    public static final MslError USERAUTH_REQUIRED = new ProxyMslError(5000, ResponseCode.FAIL, "User authentication required.", true);
    public static final MslError USERAUTH_CANNOT_FAILOVER = new ProxyMslError(5001, ResponseCode.TRANSIENT_FAILURE, "User authentication cannot be handled during failover.", false);
    
    // 6 Message
    public static final MslError NONREPLAYABLE_ID_CHECK_REQUIRED = new ProxyMslError(6000, ResponseCode.FAIL, "Non-replayable message check required.", true);
    public static final MslError SERVICETOKEN_REQUIRES_MASTERTOKEN = new ProxyMslError(6001, ResponseCode.FAIL, "Cannot attach entity service token to a message with no master token.", false);
    public static final MslError SERVICETOKEN_REQUIRES_USERIDTOKEN = new ProxyMslError(6002, ResponseCode.FAIL, "Cannot attach user service token to a message with no user ID token.", false);
    
    // 7 Key Exchange
    public static final MslError KEYX_REQUIRED = new ProxyMslError(7000, ResponseCode.FAIL, "Key exchange required.", true);
    
    // 9 Internal Errors
    //public static final MslError PROXY_ACTION_REQUIRED = new ProxyMslError(9000, ResponseCode.FAIL, "External processing by the proxied MSL service is required.", true);
    
    /**
     * Construct a Proxy MSL error with the specified internal and response
     * error codes and message.
     *
     * @param internalCode internal error code.
     * @param responseCode response error code.
     * @param msg developer-consumable error message.
     * @param requiresExternalProcessing true if this error indicates the
     *        message requires processing by the external MSL service.      
     */
    protected ProxyMslError(final int internalCode, final ResponseCode responseCode, final String msg, final boolean requiresExternalProcessing) {
        super(OFFSET + internalCode, responseCode, msg);
        this.requiresExternalProcessing = requiresExternalProcessing;
    }
    
    /**
     * Check if the given MSL error indicates a message required processing by
     * the external MSL service being proxied.
     * 
     * @param e the MSL error to check.
     * @return true if the MSL error indicates the message requires processing
     *         by the external MSL service.
     */
    public static boolean isExternalProcessingRequired(final MslError e) {
        // FIXME this function may be unnecessary.
        return (e instanceof ProxyMslError && ((ProxyMslError)e).requiresExternalProcessing);
    }
    
    /** External processing required. */
    private final boolean requiresExternalProcessing;
}
