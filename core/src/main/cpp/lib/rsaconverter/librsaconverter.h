/* librsaconverter.h 

Copyright 2009 Mounir IDRASSI (mounir.idrassi@idrix.fr)

This file is part of RSAConverter.

The RSAConverter is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at your
option) any later version.

The RSAConverter is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the RSAConverter.  If not, see http://www.gnu.org/licenses/.  */

#ifndef LIBRSACONVERTER_H
#define LIBRSACONVERTER_H

#include <openssl/bn.h>

#ifdef  __cplusplus
extern "C" {
#endif


   /*
   * Timeout in seconds for the the conversion
   * from CRT to SFM in case the input parameters
   * are wrong and there is no valid SFM paramters
   */
#define SFMTOCRT_TIMEOUT  (5*60)

   /*
   * Check the consistency of an RSA SFM key
   *
   * return 1 on success, 0 on failure
   */
   int CheckRsaSfmKey(const BIGNUM* n, const BIGNUM* e, const BIGNUM* d);

   /*
   * compute the RSA CRT components from the modulus,
   * the public exponent and the private exponent
   *
   * return 1 on succes, 0 on failure (timeout)
   */
   int SfmToCrt( const BIGNUM* n,
      const BIGNUM* e,
      const BIGNUM* d,
      BIGNUM* p,
      BIGNUM* q,
      BIGNUM* dp,
      BIGNUM* dq,
      BIGNUM* u);

   /*
   * compute the RSA modulus, the public exponent and 
   * the private exponent from the RSA CRT components
   *
   * return 1 on succes, 0 on failure (inconsistency)
   */
   int CrtToSfm( const BIGNUM* p,
      const BIGNUM* q,
      const BIGNUM* dp,
      const BIGNUM* dq,
      BIGNUM* n,
      BIGNUM* e,
      BIGNUM* d);


#ifdef  __cplusplus
}
#endif

#endif
