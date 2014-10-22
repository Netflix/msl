package com.netflix.msl.server.common;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.server.configuration.msg.ServerMessageContext;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.server.configuration.util.ServerMslContext;
import com.netflix.msl.userauth.UserAuthenticationScheme;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Future;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class BaseServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    protected static final String payload = "Hello";
    protected static final String error = "Error";
    private static final int TIMEOUT = 25000;
    private boolean isNullCryptoContext;
    private boolean setConsoleFilterStreamFactory;
    private EntityAuthenticationScheme entityAuthScheme;
    private int numThreads;
    private TokenFactoryType tokenFactoryType;
    private long initialSequenceNum;
    private boolean isMessageEncrypted;
    private boolean isIntegrityProtected;
    private final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories;
    private final List<UserAuthenticationScheme> unSupportedUserAuthFactories;
    private final List<KeyExchangeScheme> unSupportedKeyxFactories;
    protected ServerMslContext mslCtx;
    protected ServerMessageContext msgCtx;
    private MslControl mslCtrl;

    public BaseServlet(final int numThreads, final EntityAuthenticationScheme entityAuthScheme, final TokenFactoryType tokenFactoryType,
                       final long initialSequenceNum, final boolean isMessageEncrypted, final boolean isIntegrityProtected,
                       final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories,
                       final List<UserAuthenticationScheme> unSupportedUserAuthFactories, final List<KeyExchangeScheme> unSupportedKeyxFactories,
                       final boolean isNullCryptoContext, final boolean setConsoleFilterStreamFactory) throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        this.numThreads = numThreads;
        this.entityAuthScheme = entityAuthScheme;
        this.tokenFactoryType = tokenFactoryType;
        this.initialSequenceNum = initialSequenceNum;
        this.isMessageEncrypted = isMessageEncrypted;
        this.isIntegrityProtected = isIntegrityProtected;
        this.unSupportedEntityAuthFactories = unSupportedEntityAuthFactories;
        this.unSupportedUserAuthFactories = unSupportedUserAuthFactories;
        this.unSupportedKeyxFactories = unSupportedKeyxFactories;
        this.isNullCryptoContext = isNullCryptoContext;
        this.setConsoleFilterStreamFactory = setConsoleFilterStreamFactory;
        configure();
    }

    private void configure() throws MslCryptoException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, MslEncodingException {
        mslCtrl = new MslControl(numThreads);
        if(setConsoleFilterStreamFactory) {
            mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());
        }
        /**
         * Msl Context Configuration
         */
        mslCtx = new ServerMslContext(entityAuthScheme, false, tokenFactoryType, initialSequenceNum, unSupportedEntityAuthFactories,
                unSupportedUserAuthFactories, unSupportedKeyxFactories, isNullCryptoContext);

        /**
         * Message Context Configuration
         */
        msgCtx = new ServerMessageContext(mslCtx, payload.getBytes(), isMessageEncrypted);
        msgCtx.setIntegrityProtected(isIntegrityProtected);
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");

        super.service(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();

        Map<String, String[]> params = request.getParameterMap();
        for (Entry<String,String[]> entry : params.entrySet()) {
            try {
                String key = entry.getKey();
                String[] value = entry.getValue();
                setPrivateVariable(out, key, value);
            } catch (Exception e) {
                e.printStackTrace();
                out.println(e.getMessage());
            }
        }
        try {
            configure();
        } catch (Exception e) {
            e.printStackTrace();
            out.println(e.getMessage());
        }
        out.println(request.getServletPath());
        out.close();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final InputStream inStream = request.getInputStream();
        final OutputStream outStream = response.getOutputStream();
        InputStream mslInputStream = null;


        byte[] buffer = new byte[5];

        try {
            Future<MessageInputStream> msgInputStream = mslCtrl.receive(mslCtx, msgCtx, inStream, outStream, TIMEOUT);

            mslInputStream = msgInputStream.get();
            if (mslInputStream == null) return;

            do {
                final int bytesRead = mslInputStream.read(buffer);
                if (bytesRead == -1) break;
            } while (true);

            //Checking the the received payload is the same as the one the client sent
            if (!Arrays.equals(payload.getBytes(), buffer)) {
                msgCtx.setBuffer(error.getBytes());
                mslCtrl.respond(mslCtx, msgCtx, inStream, outStream, msgInputStream.get(), TIMEOUT);
                throw new IllegalStateException("PayloadBytes is not as expected: " + Arrays.toString(buffer));
            }
            msgCtx.setBuffer(buffer);
            mslCtrl.respond(mslCtx, msgCtx, inStream, outStream, msgInputStream.get(), TIMEOUT);

        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (mslInputStream != null) {
                mslInputStream.close();
            }
        }
    }

    private void setPrivateVariable(PrintWriter out, String key, String[] values) throws Exception {
        if (key.equals("numthreads")) {
            this.numThreads = Integer.parseInt(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("entityauthscheme")) {
            this.entityAuthScheme = EntityAuthenticationScheme.getScheme(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("tokenfactorytype")) {
            this.tokenFactoryType = TokenFactoryType.valueOf(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("initialseqnum")) {
            this.initialSequenceNum = Long.parseLong(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("encrypted")) {
            this.isMessageEncrypted = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("intProtected")) {
            this.isIntegrityProtected = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else if(key.equals("consoleFilterStreamFactory")) {
            this.setConsoleFilterStreamFactory = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else if(key.equals("nullCryptoContext")) {
            this.isNullCryptoContext = Boolean.parseBoolean(values[0]);
            out.println(key + ":" + values[0]);
        } else if (key.equals("unsupentityauthfact")) {
            this.unSupportedEntityAuthFactories.clear();
            for (String entityAuth : values) {
                this.unSupportedEntityAuthFactories.add(EntityAuthenticationScheme.getScheme(entityAuth));
                out.println(key + ": " + entityAuth);
            }
        } else if (key.equals("unsupuserauthfact")) {
            this.unSupportedUserAuthFactories.clear();
            for (String userAuth : values) {
                this.unSupportedUserAuthFactories.add(UserAuthenticationScheme.getScheme(userAuth));
                out.println(key + ": " + userAuth);
            }
        } else if (key.equals("unsupkeyexfact")) {
            this.unSupportedKeyxFactories.clear();
            for (String keyEx : values) {
                this.unSupportedKeyxFactories.add(KeyExchangeScheme.getScheme(keyEx));
                out.println(key + ": " + keyEx);
            }
        } else {
            throw new Exception("Invalid parameter: " + key);
        }
    }


    protected String getBody(HttpServletRequest request) throws IOException {

        String body = null;
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;

        try {
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                bufferedReader.mark(100000);
                char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
                bufferedReader.reset();
            } else {
                stringBuilder.append("");
            }
        } catch (IOException ex) {
            throw ex;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }

        body = stringBuilder.toString();
        return body;
    }
}
