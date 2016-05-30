/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package oneshot;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslException;
import com.netflix.msl.io.JavaUrl;
import com.netflix.msl.io.Url;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Oneshot {
    /** Local entity identity. */
    private static final String LOCAL_IDENTITY = "local-identity";
    
    /** Remote entity identity. */
    private static final String REMOTE_IDENTITY = "remote-identity"; 
    /** Remote entity RSA public key. */
    private static final String REMOTE_RSA_PUBKEY_B64 = 
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l" +
        "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==";
    
    /** User email address; {@code null} for no user. */
    private static final String EMAIL = "user@domain.com";
    /** User password; {@code null} for no user. */
    private static final String PASSWORD = "password";
    
    /** MSL timeout in milliseconds. */
    private static final int TIMEOUT = 30 * 1000;
    
	/**
	 * @param localIdentity local entity identity.
	 * @param remoteIdentity remote entity identity.
	 * @param remoteRsaPubkeyB64 base64-encoded remote entity public key in
	 *        X.509 format.
	 * @param email user email address. May be {@code null}.
	 * @param password user password. May be {@code null}.
	 * @throws NoSuchAlgorithmException if the RSA algorithm is not supported.
	 * @throws InvalidKeySpecException if the public key is invalid.
	 */
	public Oneshot(final String localIdentity, final String remoteIdentity, final String remoteRsaPubkeyB64, final String email, final String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Create MSL control.
        this.ctrl = new MslControl(0);
        
	    // Setup remote entity public key.
	    final byte[] pubkeyBytes = Base64.decode(remoteRsaPubkeyB64);
	    final X509EncodedKeySpec pubkeySpec = new X509EncodedKeySpec(pubkeyBytes);
	    final KeyFactory factory = KeyFactory.getInstance("RSA");
	    final PublicKey pubkey = factory.generatePublic(pubkeySpec);
	    final OneshotRsaStore rsaStore = new OneshotRsaStore(remoteIdentity, pubkey);
	    
	    // Create MSL context.
		this.ctx = new OneshotMslContext(localIdentity, rsaStore);
		
		// Save user account information.
		this.email = email;
		this.password = password;
	}
	
	/**
	 * @param remoteEntity remote entity URL.
	 * @param data application data.
	 * @return the application response data or {@code null} if interrupted or
	 *         cancelled.
	 * @throws MslException if there is an MSL error.
	 * @throws ExecutionException if there is a problem making the request.
	 * @throws InterruptedException if the request was interrupted.
	 * @throws OneshotErrorResponse if the remote entity returned a MSL error.
	 * @throws IOException if there is an error reading the response.
	 */
	public byte[] request(final Url remoteEntity, final byte[] data) throws MslException, ExecutionException, InterruptedException, OneshotErrorResponse, IOException {
	    // Setup message context.
	    final MessageContext msgCtx = new OneshotMessageContext(data, email, password);
	    
	    // Make the request.
	    MessageInputStream mis = null;
	    try {
	        final Future<MslChannel> future = ctrl.request(ctx, msgCtx, remoteEntity, TIMEOUT);
	        final MslChannel channel = future.get();
	        
	        // Check if cancelled or interrupted. Not expected.
	        if (channel == null)
	            return null;
	        
	        // Grab the message input stream.
	        mis = channel.input;
	    } catch (final ExecutionException | InterruptedException e) {
	        final Throwable cause = e.getCause();
	        if (cause instanceof MslException)
	            throw (MslException)cause;
	        throw e;
	    }
        
        // Check for an error response.
        final ErrorHeader errorHeader = mis.getErrorHeader();
        if (errorHeader != null)
            throw new OneshotErrorResponse(errorHeader);

        // Read all the response data.
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final byte[] buffer = new byte[16384];
        do {
            final int count = mis.read(buffer);
            if (count == -1)
                return baos.toByteArray();
            baos.write(buffer, 0, count);
        } while (true);
	}
	
	/** MSL control. */
	private final MslControl ctrl;
	/** MSL context. */
	private final MslContext ctx;
	/** User email address. */
	private final String email;
	/** User password. */
	private final String password;
	
	/**
	 * <p>Issue a oneshot request/response to a MSL endpoint.</p>
	 * 
	 * <p>The first argument is a URL pointing at the remote entity. The second
	 * argument identifes the application request data source: either a
	 * filename or the '-' character to read from stdin.</p>
	 * 
	 * <p>The response data is printed to stdout. Any errors or exceptions are
	 * printed to stderr.</p>
	 */
	public static void main(final String[] args) {
	    try {
	        if (args.length != 2) {
	            System.err.println("Usage: oneshot url file");
	            System.err.println("  use '-' for file to read from STDIN");
	            System.exit(1);
	        }

            // Grab remote URL and data file.
            final Url url = new JavaUrl(new URL(args[0]));
	        final String file = args[1];

	        // Read request data.
	        final byte[] request;
	        final InputStream is = (file.equals("-"))
	            ? System.in
	                : new FileInputStream(file);

	        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        final byte[] buffer = new byte[16384];
	        do {
	            final int count = is.read(buffer);
	            if (count == -1) {
	                request = baos.toByteArray();
	                break;
	            }
                baos.write(buffer, 0, count);
            } while (true);

	        // Send request and print application response data.
	        final Oneshot oneshot = new Oneshot(LOCAL_IDENTITY, REMOTE_IDENTITY, REMOTE_RSA_PUBKEY_B64, EMAIL, PASSWORD);
	        final byte[] response = oneshot.request(url, request);
	        System.out.write(response);
	    } catch (final Throwable t) {
	        // Print the exception message and stack trace for normal errors.
	        if (!(t instanceof OneshotErrorResponse)) {
	            t.printStackTrace(System.err);
	            return;
	        }
	        
	        // Print the MSL error details for MSL error responses.
	        final OneshotErrorResponse oer = (OneshotErrorResponse)t;
	        final ErrorHeader errorHeader = oer.getErrorHeader();
	        final ResponseCode errorCode = errorHeader.getErrorCode();
	        final int internalCode = errorHeader.getInternalCode();
	        final String errorMessage = errorHeader.getErrorMessage();
	        final String userMessage = errorHeader.getUserMessage();
	        System.err.println("MSL Error: " + errorCode + " (" + internalCode + ")");
	        System.err.println("\t" + errorMessage);
	        if (userMessage != null)
	            System.err.println("\t" + userMessage);
	    }
	}
}
