package com.netflix.msl.server.servlet;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.server.common.BaseServlet;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;

import javax.servlet.annotation.WebServlet;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * User: skommidi
 * Date: 8/27/14
 */
@WebServlet(urlPatterns = "/null", loadOnStartup = 1)
public class NullServlet extends BaseServlet {

    private static final long serialVersionUID = 1L;

    private static final long SEQUENCE_NUMBER = 8L;
    private static final int NUM_THREADS = 0;

    public NullServlet() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        super(NUM_THREADS, EntityAuthenticationScheme.NONE, TokenFactoryType.NOT_ACCEPT_NON_REPLAYABLE_ID,
                SEQUENCE_NUMBER, false, false, null, null, null, true, true);
        System.out.println("======================>> Null Servlet Initialization Ended <<======================");
    }
}
