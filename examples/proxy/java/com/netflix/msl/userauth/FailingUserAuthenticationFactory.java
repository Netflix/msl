/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.userauth;

import org.json.JSONObject;

import com.netflix.msl.MslError;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>Failing user authentication factory.</p>
 * 
 * <p>When used, this factory throws a {@link MslUserAuthException}
 * containing the MSL error specified when constructed.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FailingUserAuthenticationFactory extends UserAuthenticationFactory {
    /**
     * Create a new failing user authentication factory for the specified
     * scheme.
     * 
     * @param scheme the user authentication scheme.
     * @param error the error to throw.
     */
    public FailingUserAuthenticationFactory(final UserAuthenticationScheme scheme, final MslError error) {
        super(scheme);
        this.error = error;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, org.json.JSONObject)
     */
    @Override
    public UserAuthenticationData createData(MslContext ctx, MasterToken masterToken, JSONObject userAuthJO) throws MslUserAuthException {
        throw new MslUserAuthException(error);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, UserIdToken userIdToken) throws MslUserAuthException {
        throw new MslUserAuthException(error);
    }

    /** MSL error. */
    private final MslError error;
}
