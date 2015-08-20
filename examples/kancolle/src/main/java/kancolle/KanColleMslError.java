/**
 * Copyright 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kancolle;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslError;

/**
 * <p>KanColle error codes and descriptions.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleMslError extends MslError {
    /** KanColle internal error code offset value. */
    private static final int OFFSET = 100000;
    
    // 0 Message Security Layer
    
    // 1 Master Token
    public static final MslError KANMUSU_REVOKED_DESTROYED = new KanColleMslError(1000, ResponseCode.ENTITYDATA_REAUTH, "Kanmusu revoked because it was confirmed destroyed.");
    public static final MslError KANMUSU_REVOKED_UNKNOWN = new KanColleMslError(1001, ResponseCode.ENTITYDATA_REAUTH, "Kanmusu revoked because the ship identity is unknown.");
    public static final MslError NAVALPORT_REVOKED_DESTROYED = new KanColleMslError(1002, ResponseCode.ENTITYDATA_REAUTH, "Naval port revoked because it was confirmed destroyed.");
    public static final MslError NAVALPORT_REVOKED_UNKNOWN = new KanColleMslError(1003, ResponseCode.ENTITYDATA_REAUTH, "Naval port revoked because the callsign is unknown.");
    public static final MslError NAVALPORT_REVOKED_INACTIVE = new KanColleMslError(1004, ResponseCode.ENTITYDATA_REAUTH, "Naval port revoked because it is inactive.");
        
    // 2 User ID Token
    public static final MslError OFFICER_REVOKED_DISCHARGED = new KanColleMslError(2000, ResponseCode.USERDATA_REAUTH, "Officer revoked because it was discharged.");
    public static final MslError OFFICER_REVOKED_COURT_MARTIALED = new KanColleMslError(2001, ResponseCode.USERDATA_REAUTH, "Officer revoked because it was court martialed.");
    public static final MslError OFFICER_REVOKED_DECEASED = new KanColleMslError(2002, ResponseCode.USERDATA_REAUTH, "Officer revoked because it is deceased.");
    public static final MslError OFFICER_REVOKED_KIA = new KanColleMslError(2003, ResponseCode.USERDATA_REAUTH, "Officer revoked because it was killed in action.");
    public static final MslError OFFICER_REVOKED_UNKNOWN = new KanColleMslError(2004, ResponseCode.USERDATA_REAUTH, "Officer revoked because it is unknown.");
    
    // 3 Service Token
    
    // 4 Entity Authentication
    public static final MslError ENTITYAUTH_KANMUSU_DESTROYED = new KanColleMslError(4000, ResponseCode.ENTITYDATA_REAUTH, "Kanmusu confirmed destroyed.");
    public static final MslError ENTITYAUTH_NAVALPORT_DESTROYED = new KanColleMslError(4001, ResponseCode.ENTITYDATA_REAUTH, "Naval port confirmed destroyed.");
    public static final MslError ENTITYAUTH_NAVALPORT_INACTIVE = new KanColleMslError(4002, ResponseCode.ENTITYDATA_REAUTH, "Naval port inactive.");
    public static final MslError KANMUSU_ILLEGAL_IDENTITY = new KanColleMslError(4003, ResponseCode.ENTITYDATA_REAUTH, "Kanmusu type or name contains a colon.");
    public static final MslError NAVALPORT_ILLEGAL_IDENTITY = new KanColleMslError(4004, ResponseCode.ENTITYDATA_REAUTH, "Naval port callsign contains a colon.");
    
    // 5 User Authentication
    public static final MslError OFFICER_FINGERPRINT_INCORRECT = new KanColleMslError(5000, ResponseCode.USERDATA_REAUTH, "Officer name or fingerprint is incorrect.");
    public static final MslError OFFICER_NOT_FOUND = new KanColleMslError(5001, ResponseCode.USERDATA_REAUTH, "Officer name not found.");
    public static final MslError USERAUTH_OFFICER_DISCHARGED = new KanColleMslError(5002, ResponseCode.USERDATA_REAUTH, "Officer was honorably discharged.");
    public static final MslError USERAUTH_OFFICER_COURT_MARTIALED = new KanColleMslError(5003, ResponseCode.USERDATA_REAUTH, "Officer was court martialed.");
    public static final MslError USERAUTH_OFFICER_KIA = new KanColleMslError(5004, ResponseCode.USERDATA_REAUTH, "Officer confirmed killed in action.");
    public static final MslError USERAUTH_OFFICER_DECEASED = new KanColleMslError(5005, ResponseCode.USERDATA_REAUTH, "Officer confirmed deceased.");
    
    // 6 Message
    public static final MslError MSG_TYPE_UNKNOWN = new KanColleMslError(6001, ResponseCode.FAIL, "Message type unknown.");
    public static final MslError MSG_RECORD_COUNT_INVALID = new KanColleMslError(6002, ResponseCode.FAIL, "Message record count is not a number.");
    public static final MslError MSG_RECORDS_TRUNCATED = new KanColleMslError(6003, ResponseCode.FAIL, "Premature end of message records.");
    public static final MslError MSG_RECORD_NUMBER_MISSING = new KanColleMslError(6004, ResponseCode.FAIL, "Message record is missing the initial record number.");
    public static final MslError MSG_RECORD_NUMBER_MISMATCH = new KanColleMslError(6005, ResponseCode.FAIL, "Message record number is incorrect.");
    
    // 7 Key Exchange
    
    // 9 Internal Errors
    
    /**
     * Construct a KanColle MSL error with the specified internal and response
     * error codes and message.
     *
     * @param internalCode internal error code.
     * @param responseCode response error code.
     * @param message developer-consumable error message.
     */
    protected KanColleMslError(final int internalCode, final ResponseCode responseCode, final String msg) {
        super(OFFSET + internalCode, responseCode, msg);
    }
}
