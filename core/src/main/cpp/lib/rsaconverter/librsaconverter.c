/* librsaconverter.c 

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

#include "librsaconverter.h"
#include <time.h>

/*
* Implement the extended GCD algorithm that is missing from OpenSSL
*/
static void extended_gcd(BIGNUM* v, BIGNUM* a, BIGNUM* b, BIGNUM* x, BIGNUM* y)
{
   BN_CTX* ctx = BN_CTX_new();
   BIGNUM* g = NULL;
   BIGNUM* u = NULL;
   BIGNUM* A = NULL;
   BIGNUM* B = NULL;
   BIGNUM* C = NULL;
   BIGNUM* D = NULL;
   BIGNUM* tmp = NULL;
   BIGNUM* xx = NULL;
   BIGNUM* yy = NULL;

   BN_CTX_start(ctx);

   g = BN_CTX_get(ctx);
   u = BN_CTX_get(ctx);
   A = BN_CTX_get(ctx);
   B = BN_CTX_get(ctx);
   C = BN_CTX_get(ctx);
   D = BN_CTX_get(ctx);
   tmp = BN_CTX_get(ctx);
   xx = BN_CTX_get(ctx);
   yy = BN_CTX_get(ctx);

   BN_set_word(g, 1);
   BN_copy(xx, x);
   BN_copy(yy, y);

   while (!BN_is_odd(xx) && !BN_is_odd(yy))
   {
      BN_rshift1(xx, xx);
      BN_rshift1(yy, yy);
      BN_lshift1(g,g);
   }

   BN_copy(u, xx);
   BN_copy(v, yy);
   BN_set_word(A, 1);
   BN_set_word(B, 0);
   BN_set_word(C, 0);
   BN_set_word(D, 1);

   while (1)
   {
      while (!BN_is_odd(u))
      {
         BN_rshift1(u, u);
         if (!BN_is_odd(A) && !BN_is_odd(B))
         {
            BN_rshift1(A, A);
            BN_rshift1(B, B);
         }
         else
         {
            BN_add(A,A,yy);
            BN_rshift1(A, A);

            BN_sub(tmp, B, xx);
            BN_rshift1(B, tmp);
         }
      }

      while (!BN_is_odd(v))
      {
         BN_rshift1(v, v);
         if (!BN_is_odd(C) && !BN_is_odd(D))
         {
            BN_rshift1(C, C);
            BN_rshift1(D, D);
         }
         else
         {
            BN_add(C,C,yy);
            BN_rshift1(C, C);

            BN_sub(tmp, D, xx);
            BN_rshift1(D, tmp);
         }
      }

      if (BN_cmp(u, v) >= 0)
      {
         BN_sub(tmp, u, v);
         BN_copy(u, tmp);

         BN_sub(tmp, A, C);
         BN_copy(A, tmp);

         BN_sub(tmp, B, D);
         BN_copy(B, tmp);
      }
      else
      {
         BN_sub(tmp, v, u);
         BN_copy(v, tmp);

         BN_sub(tmp, C, A);
         BN_copy(C, tmp);

         BN_sub(tmp, D, B);
         BN_copy(D, tmp);
      }

      if (BN_is_zero(u))
      {
         BN_copy(a, C);
         BN_copy(b, D);
         BN_mul(tmp, g, v, ctx);
         BN_copy(v, tmp);
         break;
      }
   }

   BN_CTX_end(ctx);
   BN_CTX_free(ctx);
}


int CheckRsaSfmKey(const BIGNUM* n, const BIGNUM* e, const BIGNUM* d)
{
   BIGNUM *m, *c, *m1;
   BN_CTX *ctx;
   int iResult = 0;

   ctx = BN_CTX_new();
   BN_CTX_start(ctx);

   m = BN_CTX_get(ctx);
   m1 = BN_CTX_get(ctx);
   c = BN_CTX_get(ctx);

   BN_pseudo_rand_range(m, n);

   BN_mod_exp(c, m, e, n, ctx);
   BN_mod_exp(m1, c, d, n, ctx);

   iResult = (BN_cmp(m, m1) == 0)? 1 : 0;

   BN_CTX_end(ctx);
   BN_CTX_free(ctx);
   return iResult;
}


int SfmToCrt( const BIGNUM* n,
             const BIGNUM* e,
             const BIGNUM* d,
             BIGNUM* p,
             BIGNUM* q,
             BIGNUM* dp,
             BIGNUM* dq,
             BIGNUM* u)
{
   int iResult = 0;
   BN_CTX* ctx;
   BIGNUM  *k, *g, *kt, *rem;
   BIGNUM  *gk, *sq;
   BIGNUM* Gcd;
   unsigned long i,t;
   time_t start, diff;

   ctx = BN_CTX_new();
   BN_CTX_start(ctx);

   k = BN_CTX_get(ctx);
   kt = BN_CTX_get(ctx);  
   rem = BN_CTX_get(ctx);
   g = BN_CTX_get(ctx);
   gk = BN_CTX_get(ctx);
   sq = BN_CTX_get(ctx);
   Gcd = BN_CTX_get(ctx);

   BN_mul(k, e, d, ctx);
   BN_sub_word(k, 1);

   t = 0;
   while(!BN_is_bit_set(k,t))
      t++;

   start = time(NULL);

   while(1)
   {
      diff = time(NULL) - start;
      if (diff > SFMTOCRT_TIMEOUT)
         break;

      BN_copy(kt, k);
      BN_pseudo_rand_range(g, n);

      for(i=0;i<t;i++)
      {
         BN_rshift1(kt, kt);
         BN_mod_exp(gk, g, kt, n, ctx);         

         if (!BN_is_one(gk))
         {
            BN_sqr(sq, gk, ctx);
            BN_mod(rem, sq, n, ctx);

            if(BN_is_one(rem))
               break;
         }
      }

      if(i < t)
      {
         BN_sub_word(gk, 1);
         BN_gcd(Gcd, gk, n, ctx);
         if(!BN_is_one(Gcd))
            break;
      }
   }

   if (diff <= SFMTOCRT_TIMEOUT)
   {
      BN_copy(p, Gcd);
      BN_div(q, NULL, n, p, ctx);

      if (BN_is_prime_ex(p,50, ctx, NULL) && BN_is_prime_ex(q,50, ctx, NULL))
      {
         if (BN_cmp(q, p) > 0)
         {
            BN_swap(p,q);
         }

         BN_sub_word(p, 1);
         BN_sub_word(q, 1);

         BN_mod(dp, d, p, ctx);
         BN_mod(dq, d, q, ctx);

         BN_add_word(p, 1);
         BN_add_word(q, 1);

         BN_mod_inverse(u, q, p, ctx);

         iResult = 1;
      }
   }

   BN_CTX_end(ctx);
   BN_CTX_free(ctx);

   return iResult;
}


int CrtToSfm( const BIGNUM* p,
             const BIGNUM* q,
             const BIGNUM* dp,
             const BIGNUM* dq,
             BIGNUM* n,
             BIGNUM* e,
             BIGNUM* d)
{
   BN_CTX* ctx = BN_CTX_new();
   int iResult = 0;
   BIGNUM *g, *v, *diff, *k, *r, *l, *u;
   BIGNUM *pp, *qq, *dpp, *dqq;

   BN_CTX_start(ctx);

   pp = BN_CTX_get(ctx);
   qq = BN_CTX_get(ctx);
   dpp = BN_CTX_get(ctx);
   dqq = BN_CTX_get(ctx);

   g = BN_CTX_get(ctx);
   v = BN_CTX_get(ctx);
   u = BN_CTX_get(ctx);
   diff = BN_CTX_get(ctx);
   k = BN_CTX_get(ctx);
   r = BN_CTX_get(ctx);
   l = BN_CTX_get(ctx);

   BN_copy(pp, p);
   BN_copy(qq, q);
   BN_copy(dpp, dp);
   BN_copy(dqq, dq);

   BN_mul(n, pp, qq, ctx);

   if(BN_cmp(dpp,dqq) < 0)
   {
      BN_swap(dpp,dqq);
      BN_swap(pp,qq);
   }

   BN_sub_word(pp, 1);
   BN_sub_word(qq, 1);

   extended_gcd(g,u,v,pp,qq);
   BN_sub(diff,dpp,dqq);
   BN_div(k, NULL, diff, g, ctx);

   BN_mul(r,k,u, ctx);
   BN_mul(k,r,pp, ctx);
   BN_sub(d, dpp, k);

   BN_mul(k,pp,qq, ctx);
   BN_div(l, NULL,k,g, ctx);

   BN_mod(r,d,l, ctx);
   if (!BN_is_zero(r) && BN_is_negative(r))
      BN_add(d,l,r);
   else
      BN_copy(d,r);

   BN_mod_inverse(e,d,l, ctx);
   BN_mod_inverse(d,e,k, ctx);

   if (!BN_is_zero(d) && !BN_is_negative(d))
   {
      BN_mod(r,d,pp, ctx);
      if (0 == BN_cmp(r, dpp))
      {
         if (CheckRsaSfmKey(n,e,d))
            iResult = 1;
      }
   }


   BN_CTX_end(ctx);
   BN_CTX_free(ctx);

   return iResult;
}

