package com.netflix.msl.server.configuration.msg;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MockMessageContext;
import com.netflix.msl.server.configuration.util.ServerMslContext;
import com.netflix.msl.userauth.UserAuthenticationScheme;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class ServerMessageContext extends MockMessageContext {

    private byte[] buffer;

    /**
     * Create a new test message context.
     */
    public ServerMessageContext(ServerMslContext mslCtx, byte[] payloadBytes, boolean messageEncrypted) throws MslCryptoException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        super(mslCtx, null, UserAuthenticationScheme.EMAIL_PASSWORD);
        super.setUserAuthData(null);
        super.setKeyRequestData(new HashSet<KeyRequestData>());
        super.setEncrypted(messageEncrypted);
        this.buffer = payloadBytes;
    }

    public void setBuffer(byte[] buffer) {
        this.buffer = buffer;
    }

    public void write(final MessageOutputStream output) throws IOException {
        output.write(buffer);
        output.flush();
        output.close();
    }
}
