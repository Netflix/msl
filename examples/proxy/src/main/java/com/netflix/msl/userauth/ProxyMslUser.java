package com.netflix.msl.userauth;

import com.netflix.msl.tokens.MslUser;

/**
 * <p>A MSL user that is just the user ID.</p>
 */
public class ProxyMslUser implements MslUser {
    /**
     * <p>Create a new MSL user with the given user ID.</p>
     *
     * @param userId the user ID.
     */
    public ProxyMslUser(final String userId) {
        this.userId = userId;
    }

    /**
     * @return the user ID.
     */
    public String getUserId() {
        return userId;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.MslUser#getEncoded()
     */
    @Override
    public String getEncoded() {
        return userId;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return userId;
    }

    /** User string representation. */
    private final String userId;
}
