/*
 *  Elliptic curve DSA
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/platform_util.h"

/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#if defined(MBEDTLS_ECP_RESTARTABLE)

/*
 * Sub-context for ecdsa_verify()
 */
struct mbedtls_ecdsa_restart_ver
{
    mbedtls_mpi u1, u2;     /* intermediate values  */
    enum {                  /* what to do next?     */
        ecdsa_ver_init = 0, /* getting started      */
        ecdsa_ver_muladd,   /* muladd step          */
    } state;
};

/*
 * Init verify restart sub-context
 */
static void ecdsa_restart_ver_init( mbedtls_ecdsa_restart_ver_ctx *ctx )
{
    mbedtls_mpi_init( &ctx->u1 );
    mbedtls_mpi_init( &ctx->u2 );
    ctx->state = ecdsa_ver_init;
}

/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free( mbedtls_ecdsa_restart_ver_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_mpi_free( &ctx->u1 );
    mbedtls_mpi_free( &ctx->u2 );

    ecdsa_restart_ver_init( ctx );
}

/*
 * Sub-context for ecdsa_sign()
 */
struct mbedtls_ecdsa_restart_sig
{
    int sign_tries;
    int key_tries;
    mbedtls_mpi k;          /* per-signature random */
    mbedtls_mpi r;          /* r value              */
    enum {                  /* what to do next?     */
        ecdsa_sig_init = 0, /* getting started      */
        ecdsa_sig_mul,      /* doing ecp_mul()      */
        ecdsa_sig_modn,     /* mod N computations   */
    } state;
};

/*
 * Init verify sign sub-context
 */
static void ecdsa_restart_sig_init( mbedtls_ecdsa_restart_sig_ctx *ctx )
{
    ctx->sign_tries = 0;
    ctx->key_tries = 0;
    mbedtls_mpi_init( &ctx->k );
    mbedtls_mpi_init( &ctx->r );
    ctx->state = ecdsa_sig_init;
}

/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free( mbedtls_ecdsa_restart_sig_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_mpi_free( &ctx->k );
    mbedtls_mpi_free( &ctx->r );
}

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Sub-context for ecdsa_sign_det()
 */
struct mbedtls_ecdsa_restart_det
{
    mbedtls_hmac_drbg_context rng_ctx;  /* DRBG state   */
    enum {                      /* what to do next?     */
        ecdsa_det_init = 0,     /* getting started      */
        ecdsa_det_sign,         /* make signature       */
    } state;
};

/*
 * Init verify sign_det sub-context
 */
static void ecdsa_restart_det_init( mbedtls_ecdsa_restart_det_ctx *ctx )
{
    mbedtls_hmac_drbg_init( &ctx->rng_ctx );
    ctx->state = ecdsa_det_init;
}

/*
 * Free the components of a sign_det restart sub-context
 */
static void ecdsa_restart_det_free( mbedtls_ecdsa_restart_det_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_hmac_drbg_free( &ctx->rng_ctx );

    ecdsa_restart_det_init( ctx );
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#define ECDSA_RS_ECP    &rs_ctx->ecp

/* Utility macro for checking and updating ops budget */
#define ECDSA_BUDGET( ops )   \
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_budget( grp, &rs_ctx->ecp, ops ) );

/* Call this when entering a function that needs its own sub-context */
#define ECDSA_RS_ENTER( SUB )   do {                                 \
    /* reset ops count for this call if top-level */                 \
    if( rs_ctx != NULL && rs_ctx->ecp.depth++ == 0 )                 \
        rs_ctx->ecp.ops_done = 0;                                    \
                                                                     \
    /* set up our own sub-context if needed */                       \
    if( mbedtls_ecp_restart_is_enabled() &&                          \
        rs_ctx != NULL && rs_ctx->SUB == NULL )                      \
    {                                                                \
        rs_ctx->SUB = mbedtls_calloc( 1, sizeof( *rs_ctx->SUB ) );   \
        if( rs_ctx->SUB == NULL )                                    \
            return( MBEDTLS_ERR_ECP_ALLOC_FAILED );                  \
                                                                     \
        ecdsa_restart_## SUB ##_init( rs_ctx->SUB );                 \
    }                                                                \
} while( 0 )

/* Call this when leaving a function that needs its own sub-context */
#define ECDSA_RS_LEAVE( SUB )   do {                                 \
    /* clear our sub-context when not in progress (done or error) */ \
    if( rs_ctx != NULL && rs_ctx->SUB != NULL &&                     \
        ret != MBEDTLS_ERR_ECP_IN_PROGRESS )                         \
    {                                                                \
        ecdsa_restart_## SUB ##_free( rs_ctx->SUB );                 \
        mbedtls_free( rs_ctx->SUB );                                 \
        rs_ctx->SUB = NULL;                                          \
    }                                                                \
                                                                     \
    if( rs_ctx != NULL )                                             \
        rs_ctx->ecp.depth--;                                         \
} while( 0 )

#else /* MBEDTLS_ECP_RESTARTABLE */

#define ECDSA_RS_ECP    NULL

#define ECDSA_BUDGET( ops )   /* no-op; for compatibility */

#define ECDSA_RS_ENTER( SUB )   (void) rs_ctx
#define ECDSA_RS_LEAVE( SUB )   (void) rs_ctx

#endif /* MBEDTLS_ECP_RESTARTABLE */

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi( const mbedtls_ecp_group *grp, mbedtls_mpi *x,
                       const unsigned char *buf, size_t blen )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( x, buf, use_size ) );
    if( use_size * 8 > grp->nbits )
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( x, use_size * 8 - grp->nbits ) );

    /* While at it, reduce modulo N */
    if( mbedtls_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

#if !defined(MBEDTLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
static int ecdsa_sign_restartable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( mbedtls_mpi_cmp_int( d, 1 ) < 0 || mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e ); mbedtls_mpi_init( &t );

    ECDSA_RS_ENTER( sig );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->sig != NULL )
    {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;

        /* jump to current step */
        if( rs_ctx->sig->state == ecdsa_sig_mul )
            goto mul;
        if( rs_ctx->sig->state == ecdsa_sig_modn )
            goto modn;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    *p_sign_tries = 0;
    do
    {
        if( *p_sign_tries++ > 10 )
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do
        {
            if( *p_key_tries++ > 10 )
            {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, pk, f_rng, p_rng ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
            if( rs_ctx != NULL && rs_ctx->sig != NULL )
                rs_ctx->sig->state = ecdsa_sig_mul;

mul:
#endif
            MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, &R, pk, &grp->G,
                                                  f_rng, p_rng, ECDSA_RS_ECP ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( pr, &R.X, &grp->N ) );
        }
        while( mbedtls_mpi_cmp_int( pr, 0 ) == 0 );

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && rs_ctx->sig != NULL )
            rs_ctx->sig->state = ecdsa_sig_modn;

modn:
#endif
        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET( MBEDTLS_ECP_OPS_INV + 4 );

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, &t, f_rng, p_rng ) );

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( s, pr, d ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &e, &e, s ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &e, &e, &t ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( pk, pk, &t ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( s, pk, &grp->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( s, s, &e ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( s, s, &grp->N ) );
    }
    while( mbedtls_mpi_cmp_int( s, 0 ) == 0 );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->sig != NULL )
        mbedtls_mpi_copy( r, pr );
#endif

cleanup:
    mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &k ); mbedtls_mpi_free( &e ); mbedtls_mpi_free( &t );

    ECDSA_RS_LEAVE( sig );

    return( ret );
}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( f_rng != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_restartable( grp, r, s, d, buf, blen,
                                    f_rng, p_rng, NULL ) );
}
#endif /* !MBEDTLS_ECDSA_SIGN_ALT */

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 */
static int ecdsa_sign_det_restartable( mbedtls_ecp_group *grp,
                    mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg,
                    mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_hmac_drbg_context rng_ctx;
    mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = ( grp->nbits + 7 ) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_mpi_init( &h );
    mbedtls_hmac_drbg_init( &rng_ctx );

    ECDSA_RS_ENTER( det );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->det != NULL )
    {
        /* redirect to our context */
        p_rng = &rs_ctx->det->rng_ctx;

        /* jump to current step */
        if( rs_ctx->det->state == ecdsa_det_sign )
            goto sign;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( d, data, grp_len ) );
    MBEDTLS_MPI_CHK( derive_mpi( grp, &h, buf, blen ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &h, data + grp_len, grp_len ) );
    mbedtls_hmac_drbg_seed_buf( p_rng, md_info, data, 2 * grp_len );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->det != NULL )
        rs_ctx->det->state = ecdsa_det_sign;

sign:
#endif
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    ret = mbedtls_ecdsa_sign( grp, r, s, d, buf, blen,
                              mbedtls_hmac_drbg_random, p_rng );
#else
    ret = ecdsa_sign_restartable( grp, r, s, d, buf, blen,
                      mbedtls_hmac_drbg_random, p_rng, rs_ctx );
#endif /* MBEDTLS_ECDSA_SIGN_ALT */

cleanup:
    mbedtls_hmac_drbg_free( &rng_ctx );
    mbedtls_mpi_free( &h );

    ECDSA_RS_LEAVE( det );

    return( ret );
}

/*
 * Deterministic signature wrapper
 */
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#if !defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
static int ecdsa_verify_restartable( mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r, const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &e ); mbedtls_mpi_init( &s_inv );
    mbedtls_mpi_init( &u1 ); mbedtls_mpi_init( &u2 );

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    ECDSA_RS_ENTER( ver );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->ver != NULL )
    {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if( rs_ctx->ver->state == ecdsa_ver_muladd )
            goto muladd;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if( mbedtls_mpi_cmp_int( r, 1 ) < 0 || mbedtls_mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        mbedtls_mpi_cmp_int( s, 1 ) < 0 || mbedtls_mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    ECDSA_BUDGET( MBEDTLS_ECP_OPS_CHK + MBEDTLS_ECP_OPS_INV + 2 );

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &s_inv, s, &grp->N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( pu1, &e, &s_inv ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( pu1, pu1, &grp->N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( pu2, r, &s_inv ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( pu2, pu2, &grp->N ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->ver != NULL )
        rs_ctx->ver->state = ecdsa_ver_muladd;

muladd:
#endif
    /*
     * Step 5: R = u1 G + u2 Q
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd_restartable( grp,
                     &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP ) );

    if( mbedtls_ecp_is_zero( &R ) )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if( mbedtls_mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &e ); mbedtls_mpi_free( &s_inv );
    mbedtls_mpi_free( &u1 ); mbedtls_mpi_free( &u2 );

    ECDSA_RS_LEAVE( ver );

    return( ret );
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
    ECDSA_VALIDATE_RET( grp != NULL );
    ECDSA_VALIDATE_RET( Q   != NULL );
    ECDSA_VALIDATE_RET( r   != NULL );
    ECDSA_VALIDATE_RET( s   != NULL );
    ECDSA_VALIDATE_RET( buf != NULL || blen == 0 );

    return( ecdsa_verify_restartable( grp, buf, blen, Q, r, s, NULL ) );
}
#endif /* !MBEDTLS_ECDSA_VERIFY_ALT */

/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature_restartable( mbedtls_ecdsa_context *ctx,
                           mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_mpi r, s;
    ECDSA_VALIDATE_RET( ctx  != NULL );
    ECDSA_VALIDATE_RET( hash != NULL );
    ECDSA_VALIDATE_RET( sig  != NULL );
    ECDSA_VALIDATE_RET( slen != NULL );

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    (void) f_rng;
    (void) p_rng;

    MBEDTLS_MPI_CHK( ecdsa_sign_det_restartable( &ctx->grp, &r, &s, &ctx->d,
                             hash, hlen, md_alg, rs_ctx ) );
#else
    (void) md_alg;

#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &ctx->grp, &r, &s, &ctx->d,
                         hash, hlen, f_rng, p_rng ) );
#else
    MBEDTLS_MPI_CHK( ecdsa_sign_restartable( &ctx->grp, &r, &s, &ctx->d,
                         hash, hlen, f_rng, p_rng, rs_ctx ) );
#endif /* MBEDTLS_ECDSA_SIGN_ALT */
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK( ecdsa_signature_to_asn1( &r, &s, sig, slen ) );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    return( ret );
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature( mbedtls_ecdsa_context *ctx,
                                 mbedtls_md_type_t md_alg,
                                 const unsigned char *hash, size_t hlen,
                                 unsigned char *sig, size_t *slen,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng )
{
    ECDSA_VALIDATE_RET( ctx  != NULL );
    ECDSA_VALIDATE_RET( hash != NULL );
    ECDSA_VALIDATE_RET( sig  != NULL );
    ECDSA_VALIDATE_RET( slen != NULL );
    return( mbedtls_ecdsa_write_signature_restartable(
                ctx, md_alg, hash, hlen, sig, slen, f_rng, p_rng, NULL ) );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED) && \
    defined(MBEDTLS_ECDSA_DETERMINISTIC)
int mbedtls_ecdsa_write_signature_det( mbedtls_ecdsa_context *ctx,
                               const unsigned char *hash, size_t hlen,
                               unsigned char *sig, size_t *slen,
                               mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( ctx  != NULL );
    ECDSA_VALIDATE_RET( hash != NULL );
    ECDSA_VALIDATE_RET( sig  != NULL );
    ECDSA_VALIDATE_RET( slen != NULL );
    return( mbedtls_ecdsa_write_signature( ctx, md_alg, hash, hlen, sig, slen,
                                   NULL, NULL ) );
}
#endif

/*
 * Read and check signature
 */
int mbedtls_ecdsa_read_signature( mbedtls_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    ECDSA_VALIDATE_RET( ctx  != NULL );
    ECDSA_VALIDATE_RET( hash != NULL );
    ECDSA_VALIDATE_RET( sig  != NULL );
    return( mbedtls_ecdsa_read_signature_restartable(
                ctx, hash, hlen, sig, slen, NULL ) );
}

/*
 * Restartable read and check signature
 */
int mbedtls_ecdsa_read_signature_restartable( mbedtls_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen,
                          mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    ECDSA_VALIDATE_RET( ctx  != NULL );
    ECDSA_VALIDATE_RET( hash != NULL );
    ECDSA_VALIDATE_RET( sig  != NULL );

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA +
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &r ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &s ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
    if( ( ret = mbedtls_ecdsa_verify( &ctx->grp, hash, hlen,
                                      &ctx->Q, &r, &s ) ) != 0 )
        goto cleanup;
#else
    if( ( ret = ecdsa_verify_restartable( &ctx->grp, hash, hlen,
                              &ctx->Q, &r, &s, rs_ctx ) ) != 0 )
        goto cleanup;
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if( p != end )
        ret = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    return( ret );
}

#if !defined(MBEDTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey( mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = 0;
    ECDSA_VALIDATE_RET( ctx   != NULL );
    ECDSA_VALIDATE_RET( f_rng != NULL );

    ret = mbedtls_ecp_group_load( &ctx->grp, gid );
    if( ret != 0 )
        return( ret );

   return( mbedtls_ecp_gen_keypair( &ctx->grp, &ctx->d,
                                    &ctx->Q, f_rng, p_rng ) );
}
#endif /* !MBEDTLS_ECDSA_GENKEY_ALT */

#if defined(MBEDTLS_ECP_RECOVERABLE)

// TODO: refactor and change n size
void mbedtls_fe_add(mbedtls_fe *r, mbedtls_fe *a) {
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->n[5] += a->n[5];
    r->n[6] += a->n[6];
    r->n[7] += a->n[7];
    r->n[8] += a->n[8];
    r->n[9] += a->n[9];
}

void mbedtls_fe_sqr_inner(uint32_t *r, const uint32_t *a) {
    uint64_t c, d;
    uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
    uint32_t t9, t0, t1, t2, t3, t4, t5, t6, t7;
    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

    VERIFY_BITS(a[0], 30);
    VERIFY_BITS(a[1], 30);
    VERIFY_BITS(a[2], 30);
    VERIFY_BITS(a[3], 30);
    VERIFY_BITS(a[4], 30);
    VERIFY_BITS(a[5], 30);
    VERIFY_BITS(a[6], 30);
    VERIFY_BITS(a[7], 30);
    VERIFY_BITS(a[8], 30);
    VERIFY_BITS(a[9], 26);

    /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
     */

    d  = (uint64_t)(a[0]*2) * a[9]
       + (uint64_t)(a[1]*2) * a[8]
       + (uint64_t)(a[2]*2) * a[7]
       + (uint64_t)(a[3]*2) * a[6]
       + (uint64_t)(a[4]*2) * a[5];
    /* VERIFY_BITS(d, 64); */
    /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
    t9 = d & M; d >>= 26;
    VERIFY_BITS(t9, 26);
    VERIFY_BITS(d, 38);
    /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

    c  = (uint64_t)a[0] * a[0];
    VERIFY_BITS(c, 60);
    /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
    d += (uint64_t)(a[1]*2) * a[9]
       + (uint64_t)(a[2]*2) * a[8]
       + (uint64_t)(a[3]*2) * a[7]
       + (uint64_t)(a[4]*2) * a[6]
       + (uint64_t)a[5] * a[5];
    VERIFY_BITS(d, 63);
    /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    u0 = d & M; d >>= 26; c += u0 * R0;
    VERIFY_BITS(u0, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 61);
    /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    t0 = c & M; c >>= 26; c += u0 * R1;
    VERIFY_BITS(t0, 26);
    VERIFY_BITS(c, 37);
    /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

    c += (uint64_t)(a[0]*2) * a[1];
    VERIFY_BITS(c, 62);
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
    d += (uint64_t)(a[2]*2) * a[9]
       + (uint64_t)(a[3]*2) * a[8]
       + (uint64_t)(a[4]*2) * a[7]
       + (uint64_t)(a[5]*2) * a[6];
    VERIFY_BITS(d, 63);
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    u1 = d & M; d >>= 26; c += u1 * R0;
    VERIFY_BITS(u1, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 63);
    /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    t1 = c & M; c >>= 26; c += u1 * R1;
    VERIFY_BITS(t1, 26);
    VERIFY_BITS(c, 38);
    /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[2]
       + (uint64_t)a[1] * a[1];
    VERIFY_BITS(c, 62);
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    d += (uint64_t)(a[3]*2) * a[9]
       + (uint64_t)(a[4]*2) * a[8]
       + (uint64_t)(a[5]*2) * a[7]
       + (uint64_t)a[6] * a[6];
    VERIFY_BITS(d, 63);
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    u2 = d & M; d >>= 26; c += u2 * R0;
    VERIFY_BITS(u2, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 63);
    /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    t2 = c & M; c >>= 26; c += u2 * R1;
    VERIFY_BITS(t2, 26);
    VERIFY_BITS(c, 38);
    /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[3]
       + (uint64_t)(a[1]*2) * a[2];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    d += (uint64_t)(a[4]*2) * a[9]
       + (uint64_t)(a[5]*2) * a[8]
       + (uint64_t)(a[6]*2) * a[7];
    VERIFY_BITS(d, 63);
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    u3 = d & M; d >>= 26; c += u3 * R0;
    VERIFY_BITS(u3, 26);
    VERIFY_BITS(d, 37);
    /* VERIFY_BITS(c, 64); */
    /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    t3 = c & M; c >>= 26; c += u3 * R1;
    VERIFY_BITS(t3, 26);
    VERIFY_BITS(c, 39);
    /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[4]
       + (uint64_t)(a[1]*2) * a[3]
       + (uint64_t)a[2] * a[2];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    d += (uint64_t)(a[5]*2) * a[9]
       + (uint64_t)(a[6]*2) * a[8]
       + (uint64_t)a[7] * a[7];
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    u4 = d & M; d >>= 26; c += u4 * R0;
    VERIFY_BITS(u4, 26);
    VERIFY_BITS(d, 36);
    /* VERIFY_BITS(c, 64); */
    /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    t4 = c & M; c >>= 26; c += u4 * R1;
    VERIFY_BITS(t4, 26);
    VERIFY_BITS(c, 39);
    /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[5]
       + (uint64_t)(a[1]*2) * a[4]
       + (uint64_t)(a[2]*2) * a[3];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)(a[6]*2) * a[9]
       + (uint64_t)(a[7]*2) * a[8];
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    u5 = d & M; d >>= 26; c += u5 * R0;
    VERIFY_BITS(u5, 26);
    VERIFY_BITS(d, 36);
    /* VERIFY_BITS(c, 64); */
    /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    t5 = c & M; c >>= 26; c += u5 * R1;
    VERIFY_BITS(t5, 26);
    VERIFY_BITS(c, 39);
    /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[6]
       + (uint64_t)(a[1]*2) * a[5]
       + (uint64_t)(a[2]*2) * a[4]
       + (uint64_t)a[3] * a[3];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)(a[7]*2) * a[9]
       + (uint64_t)a[8] * a[8];
    VERIFY_BITS(d, 61);
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    u6 = d & M; d >>= 26; c += u6 * R0;
    VERIFY_BITS(u6, 26);
    VERIFY_BITS(d, 35);
    /* VERIFY_BITS(c, 64); */
    /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    t6 = c & M; c >>= 26; c += u6 * R1;
    VERIFY_BITS(t6, 26);
    VERIFY_BITS(c, 39);
    /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[7]
       + (uint64_t)(a[1]*2) * a[6]
       + (uint64_t)(a[2]*2) * a[5]
       + (uint64_t)(a[3]*2) * a[4];
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x8000007C00000007ULL);
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)(a[8]*2) * a[9];
    VERIFY_BITS(d, 58);
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    u7 = d & M; d >>= 26; c += u7 * R0;
    VERIFY_BITS(u7, 26);
    VERIFY_BITS(d, 32);
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x800001703FFFC2F7ULL);
    /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    t7 = c & M; c >>= 26; c += u7 * R1;
    VERIFY_BITS(t7, 26);
    VERIFY_BITS(c, 38);
    /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)(a[0]*2) * a[8]
       + (uint64_t)(a[1]*2) * a[7]
       + (uint64_t)(a[2]*2) * a[6]
       + (uint64_t)(a[3]*2) * a[5]
       + (uint64_t)a[4] * a[4];
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x9000007B80000008ULL);
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[9] * a[9];
    VERIFY_BITS(d, 57);
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    u8 = d & M; d >>= 26; c += u8 * R0;
    VERIFY_BITS(u8, 26);
    VERIFY_BITS(d, 31);
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x9000016FBFFFC2F8ULL);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[3] = t3;
    VERIFY_BITS(r[3], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = t4;
    VERIFY_BITS(r[4], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[5] = t5;
    VERIFY_BITS(r[5], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[6] = t6;
    VERIFY_BITS(r[6], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[7] = t7;
    VERIFY_BITS(r[7], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[8] = c & M; c >>= 26; c += u8 * R1;
    VERIFY_BITS(r[8], 26);
    VERIFY_BITS(c, 39);
    /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += d * R0 + t9;
    VERIFY_BITS(c, 45);
    /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);
    VERIFY_BITS(r[9], 22);
    VERIFY_BITS(c, 46);
    /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    d    = c * (R0 >> 4) + t0;
    VERIFY_BITS(d, 56);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[0] = d & M; d >>= 26;
    VERIFY_BITS(r[0], 26);
    VERIFY_BITS(d, 30);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d   += c * (R1 >> 4) + t1;
    VERIFY_BITS(d, 53);
    // VERIFY_CHECK(d <= 0x10000003FFFFBFULL);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[1] = d & M; d >>= 26;
    VERIFY_BITS(r[1], 26);
    VERIFY_BITS(d, 27);
    // VERIFY_CHECK(d <= 0x4000000ULL);
    /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d   += t2;
    VERIFY_BITS(d, 27);
    /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = d;
    VERIFY_BITS(r[2], 27);
    /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

// TODO: refactor and change n size
void mbedtls_fe_sqr(mbedtls_fe *r, mbedtls_fe *a)
{
    mbedtls_fe_sqr_inner(r->n, a->n);
}

void mbedtls_fe_mul_inner(uint32_t *r, const uint32_t *a, const uint32_t * MBEDTLS_RESTRICT b) {
    uint64_t c, d;
    uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
    uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;
    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

    VERIFY_BITS(a[0], 30);
    VERIFY_BITS(a[1], 30);
    VERIFY_BITS(a[2], 30);
    VERIFY_BITS(a[3], 30);
    VERIFY_BITS(a[4], 30);
    VERIFY_BITS(a[5], 30);
    VERIFY_BITS(a[6], 30);
    VERIFY_BITS(a[7], 30);
    VERIFY_BITS(a[8], 30);
    VERIFY_BITS(a[9], 26);
    VERIFY_BITS(b[0], 30);
    VERIFY_BITS(b[1], 30);
    VERIFY_BITS(b[2], 30);
    VERIFY_BITS(b[3], 30);
    VERIFY_BITS(b[4], 30);
    VERIFY_BITS(b[5], 30);
    VERIFY_BITS(b[6], 30);
    VERIFY_BITS(b[7], 30);
    VERIFY_BITS(b[8], 30);
    VERIFY_BITS(b[9], 26);

    /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
     */

    d  = (uint64_t)a[0] * b[9]
       + (uint64_t)a[1] * b[8]
       + (uint64_t)a[2] * b[7]
       + (uint64_t)a[3] * b[6]
       + (uint64_t)a[4] * b[5]
       + (uint64_t)a[5] * b[4]
       + (uint64_t)a[6] * b[3]
       + (uint64_t)a[7] * b[2]
       + (uint64_t)a[8] * b[1]
       + (uint64_t)a[9] * b[0];
    /* VERIFY_BITS(d, 64); */
    /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
    t9 = d & M; d >>= 26;
    VERIFY_BITS(t9, 26);
    VERIFY_BITS(d, 38);
    /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

    c  = (uint64_t)a[0] * b[0];
    VERIFY_BITS(c, 60);
    /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
    d += (uint64_t)a[1] * b[9]
       + (uint64_t)a[2] * b[8]
       + (uint64_t)a[3] * b[7]
       + (uint64_t)a[4] * b[6]
       + (uint64_t)a[5] * b[5]
       + (uint64_t)a[6] * b[4]
       + (uint64_t)a[7] * b[3]
       + (uint64_t)a[8] * b[2]
       + (uint64_t)a[9] * b[1];
    VERIFY_BITS(d, 63);
    /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    u0 = d & M; d >>= 26; c += u0 * R0;
    VERIFY_BITS(u0, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 61);
    /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    t0 = c & M; c >>= 26; c += u0 * R1;
    VERIFY_BITS(t0, 26);
    VERIFY_BITS(c, 37);
    /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

    c += (uint64_t)a[0] * b[1]
       + (uint64_t)a[1] * b[0];
    VERIFY_BITS(c, 62);
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
    d += (uint64_t)a[2] * b[9]
       + (uint64_t)a[3] * b[8]
       + (uint64_t)a[4] * b[7]
       + (uint64_t)a[5] * b[6]
       + (uint64_t)a[6] * b[5]
       + (uint64_t)a[7] * b[4]
       + (uint64_t)a[8] * b[3]
       + (uint64_t)a[9] * b[2];
    VERIFY_BITS(d, 63);
    /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    u1 = d & M; d >>= 26; c += u1 * R0;
    VERIFY_BITS(u1, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 63);
    /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    t1 = c & M; c >>= 26; c += u1 * R1;
    VERIFY_BITS(t1, 26);
    VERIFY_BITS(c, 38);
    /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

    c += (uint64_t)a[0] * b[2]
       + (uint64_t)a[1] * b[1]
       + (uint64_t)a[2] * b[0];
    VERIFY_BITS(c, 62);
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    d += (uint64_t)a[3] * b[9]
       + (uint64_t)a[4] * b[8]
       + (uint64_t)a[5] * b[7]
       + (uint64_t)a[6] * b[6]
       + (uint64_t)a[7] * b[5]
       + (uint64_t)a[8] * b[4]
       + (uint64_t)a[9] * b[3];
    VERIFY_BITS(d, 63);
    /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    u2 = d & M; d >>= 26; c += u2 * R0;
    VERIFY_BITS(u2, 26);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(c, 63);
    /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    t2 = c & M; c >>= 26; c += u2 * R1;
    VERIFY_BITS(t2, 26);
    VERIFY_BITS(c, 38);
    /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

    c += (uint64_t)a[0] * b[3]
       + (uint64_t)a[1] * b[2]
       + (uint64_t)a[2] * b[1]
       + (uint64_t)a[3] * b[0];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    d += (uint64_t)a[4] * b[9]
       + (uint64_t)a[5] * b[8]
       + (uint64_t)a[6] * b[7]
       + (uint64_t)a[7] * b[6]
       + (uint64_t)a[8] * b[5]
       + (uint64_t)a[9] * b[4];
    VERIFY_BITS(d, 63);
    /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    u3 = d & M; d >>= 26; c += u3 * R0;
    VERIFY_BITS(u3, 26);
    VERIFY_BITS(d, 37);
    /* VERIFY_BITS(c, 64); */
    /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    t3 = c & M; c >>= 26; c += u3 * R1;
    VERIFY_BITS(t3, 26);
    VERIFY_BITS(c, 39);
    /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

    c += (uint64_t)a[0] * b[4]
       + (uint64_t)a[1] * b[3]
       + (uint64_t)a[2] * b[2]
       + (uint64_t)a[3] * b[1]
       + (uint64_t)a[4] * b[0];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[5] * b[9]
       + (uint64_t)a[6] * b[8]
       + (uint64_t)a[7] * b[7]
       + (uint64_t)a[8] * b[6]
       + (uint64_t)a[9] * b[5];
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    u4 = d & M; d >>= 26; c += u4 * R0;
    VERIFY_BITS(u4, 26);
    VERIFY_BITS(d, 36);
    /* VERIFY_BITS(c, 64); */
    /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    t4 = c & M; c >>= 26; c += u4 * R1;
    VERIFY_BITS(t4, 26);
    VERIFY_BITS(c, 39);
    /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

    c += (uint64_t)a[0] * b[5]
       + (uint64_t)a[1] * b[4]
       + (uint64_t)a[2] * b[3]
       + (uint64_t)a[3] * b[2]
       + (uint64_t)a[4] * b[1]
       + (uint64_t)a[5] * b[0];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[6] * b[9]
       + (uint64_t)a[7] * b[8]
       + (uint64_t)a[8] * b[7]
       + (uint64_t)a[9] * b[6];
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    u5 = d & M; d >>= 26; c += u5 * R0;
    VERIFY_BITS(u5, 26);
    VERIFY_BITS(d, 36);
    /* VERIFY_BITS(c, 64); */
    /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    t5 = c & M; c >>= 26; c += u5 * R1;
    VERIFY_BITS(t5, 26);
    VERIFY_BITS(c, 39);
    /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)a[0] * b[6]
       + (uint64_t)a[1] * b[5]
       + (uint64_t)a[2] * b[4]
       + (uint64_t)a[3] * b[3]
       + (uint64_t)a[4] * b[2]
       + (uint64_t)a[5] * b[1]
       + (uint64_t)a[6] * b[0];
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[7] * b[9]
       + (uint64_t)a[8] * b[8]
       + (uint64_t)a[9] * b[7];
    VERIFY_BITS(d, 61);
    /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    u6 = d & M; d >>= 26; c += u6 * R0;
    VERIFY_BITS(u6, 26);
    VERIFY_BITS(d, 35);
    /* VERIFY_BITS(c, 64); */
    /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    t6 = c & M; c >>= 26; c += u6 * R1;
    VERIFY_BITS(t6, 26);
    VERIFY_BITS(c, 39);
    /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)a[0] * b[7]
       + (uint64_t)a[1] * b[6]
       + (uint64_t)a[2] * b[5]
       + (uint64_t)a[3] * b[4]
       + (uint64_t)a[4] * b[3]
       + (uint64_t)a[5] * b[2]
       + (uint64_t)a[6] * b[1]
       + (uint64_t)a[7] * b[0];
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x8000007C00000007ULL);
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[8] * b[9]
       + (uint64_t)a[9] * b[8];
    VERIFY_BITS(d, 58);
    /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    u7 = d & M; d >>= 26; c += u7 * R0;
    VERIFY_BITS(u7, 26);
    VERIFY_BITS(d, 32);
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x800001703FFFC2F7ULL);
    /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    t7 = c & M; c >>= 26; c += u7 * R1;
    VERIFY_BITS(t7, 26);
    VERIFY_BITS(c, 38);
    /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

    c += (uint64_t)a[0] * b[8]
       + (uint64_t)a[1] * b[7]
       + (uint64_t)a[2] * b[6]
       + (uint64_t)a[3] * b[5]
       + (uint64_t)a[4] * b[4]
       + (uint64_t)a[5] * b[3]
       + (uint64_t)a[6] * b[2]
       + (uint64_t)a[7] * b[1]
       + (uint64_t)a[8] * b[0];
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x9000007B80000008ULL);
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t)a[9] * b[9];
    VERIFY_BITS(d, 57);
    /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    u8 = d & M; d >>= 26; c += u8 * R0;
    VERIFY_BITS(u8, 26);
    VERIFY_BITS(d, 31);
    /* VERIFY_BITS(c, 64); */
    // VERIFY_CHECK(c <= 0x9000016FBFFFC2F8ULL);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[3] = t3;
    VERIFY_BITS(r[3], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = t4;
    VERIFY_BITS(r[4], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[5] = t5;
    VERIFY_BITS(r[5], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[6] = t6;
    VERIFY_BITS(r[6], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[7] = t7;
    VERIFY_BITS(r[7], 26);
    /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[8] = c & M; c >>= 26; c += u8 * R1;
    VERIFY_BITS(r[8], 26);
    VERIFY_BITS(c, 39);
    /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += d * R0 + t9;
    VERIFY_BITS(c, 45);
    /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);
    VERIFY_BITS(r[9], 22);
    VERIFY_BITS(c, 46);
    /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    d    = c * (R0 >> 4) + t0;
    VERIFY_BITS(d, 56);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[0] = d & M; d >>= 26;
    VERIFY_BITS(r[0], 26);
    VERIFY_BITS(d, 30);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d   += c * (R1 >> 4) + t1;
    VERIFY_BITS(d, 53);
    // VERIFY_CHECK(d <= 0x10000003FFFFBFULL);
    /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[1] = d & M; d >>= 26;
    VERIFY_BITS(r[1], 26);
    VERIFY_BITS(d, 27);
    // VERIFY_CHECK(d <= 0x4000000ULL);
    /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d   += t2;
    VERIFY_BITS(d, 27);
    /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = d;
    VERIFY_BITS(r[2], 27);
    /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

// TODO: refactor and change n size
void mbedtls_fe_mul(mbedtls_fe *r, mbedtls_fe *a, mbedtls_fe * MBEDTLS_RESTRICT b)
{
    mbedtls_fe_mul_inner(r->n, a->n, b->n);
}

// TODO: refactor and change n size
void mbedtls_fe_set_int(mbedtls_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = r->n[5] = r->n[6] = r->n[7] = r->n[8] = r->n[9] = 0;
}

int mbedtls_fe_is_odd(const mbedtls_fe *a) {
    return a->n[0] & 1;
}

void mbedtls_fe_negate(mbedtls_fe *r, mbedtls_fe *a, int m) {
    r->n[0] = 0x3FFFC2FUL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0x3FFFFBFUL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[4];
    r->n[5] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[5];
    r->n[6] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[6];
    r->n[7] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[7];
    r->n[8] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[8];
    r->n[9] = 0x03FFFFFUL * 2 * (m + 1) - a->n[9];
}

// TODO: broken in 64
int mbedtls_fe_normalizes_to_zero(mbedtls_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint32_t z0, z1;

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL; z0  = t0; z1  = t0 ^ 0x3D0UL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

int mbedtls_fe_equal(const mbedtls_fe *a, const mbedtls_fe *b) {
    mbedtls_fe na;
    mbedtls_fe_negate(&na, a, 1);
    mbedtls_fe_add(&na, b);
    return mbedtls_fe_normalizes_to_zero(&na);
}

// TODO: refactor and change n size
int mbedtls_fe_sqrt(mbedtls_fe *r, mbedtls_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    mbedtls_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    mbedtls_fe_sqr(&x2, a);
    mbedtls_fe_mul(&x2, &x2, a);

    mbedtls_fe_sqr(&x3, &x2);
    mbedtls_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x6, &x6);
    }
    mbedtls_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x9, &x9);
    }
    mbedtls_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        mbedtls_fe_sqr(&x11, &x11);
    }
    mbedtls_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        mbedtls_fe_sqr(&x22, &x22);
    }
    mbedtls_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        mbedtls_fe_sqr(&x44, &x44);
    }
    mbedtls_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        mbedtls_fe_sqr(&x88, &x88);
    }
    mbedtls_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        mbedtls_fe_sqr(&x176, &x176);
    }
    mbedtls_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        mbedtls_fe_sqr(&x220, &x220);
    }
    mbedtls_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x223, &x223);
    }
    mbedtls_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(&t1, &t1, &x2);
    mbedtls_fe_sqr(&t1, &t1);
    mbedtls_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    mbedtls_fe_sqr(&t1, r);
    return mbedtls_fe_equal(&t1, a);
}

// TODO: shift the uint_32 array?
int mbedtls_mpi_to_fe(mbedtls_mpi *r, mbedtls_fe *m)
{
    int ret;
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( m     != NULL );

    size_t n_size = sizeof( m->n );
    size_t r_size = n_size / sizeof(mbedtls_mpi_uint);
    if (r_size < r->n || r->p == NULL) {
        // grow the size
        // MBEDTLS_MPI_CHK( mbedtls_mpi_grow( m, r->n - r_size ) );
        ret = -1;
        goto cleanup;
    }
    memset( m->n, 0, n_size );
    memcpy( m->n, &r->p, n_size );

cleanup:

    return( ret );
}

// TODO: shift the uint_32
// if m->n > 0 or size > m->n, return -1
int mbedtls_fe_to_mpi(mbedtls_fe *r, mbedtls_mpi *m)
{
    int ret;
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( m     != NULL );

    size_t r_size = sizeof( r->n );
    size_t p_size = r_size / sizeof( mbedtls_mpi_uint );
    if ( m->n > 0 && p_size > m->n ) {
        return -1;
    }
    if ( m->p == NULL ) {
        MBEDTLS_MPI_CHK( mbedtls_mpi_grow( m, p_size ) );
    }
    memset( m->p, 0, r_size );
    memcpy( m->p, &r->n, r_size );

cleanup:

    return( ret );
}


int mbedtls_ge_set_xquad(mbedtls_fe *x, mbedtls_fe *y) {
    int CURVE_B = 7;
    mbedtls_fe x2, x3, c;
    mbedtls_fe_sqr(&x2, x);
    mbedtls_fe_mul(&x3, x, &x2);
    mbedtls_fe_set_int(&c, CURVE_B);
    mbedtls_fe_add(&c, &x3);
    return mbedtls_fe_sqrt(y, &c);
}

// TODO: refactor
// create point from X
int mbedtls_set_xo_var(mbedtls_fe *x, mbedtls_fe *y, int odd) {
    if (!mbedtls_ge_set_xquad(x, y)) {
        return -1;
    }
    if (mbedtls_fe_is_odd(y) != odd) {
        mbedtls_fe_negate(y, y, 1);
    }
    return 0;
}

void mbedtls_fe_get_b32(unsigned char *r, const mbedtls_fe *a) {
    int i;
    for (i=0; i<32; i++) {
        int j;
        int c = 0;
        for (j=0; j<4; j++) {
            int limb = (8*i+2*j)/26;
            int shift = (8*i+2*j)%26;
            c |= ((a->n[limb] >> shift) & 0x3) << (2 * j);
        }
        r[31-i] = c;
    }
}

// TODO: refactor and change n size
int mbedtls_fe_set_b32(mbedtls_fe *r, mbedtls_mpi *b) {
    int i, ret;
    unsigned char a[32];
    // uint32_t n[10];
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( b, &a, 32 ) );
    r->n[0] = r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    r->n[5] = r->n[6] = r->n[7] = r->n[8] = r->n[9] = 0;
    for (i=0; i<32; i++) {
        int j;
        for (j=0; j<4; j++) {
            int limb = (8*i+2*j)/26;
            int shift = (8*i+2*j)%26;
            r->n[limb] |= (uint32_t)((a[31-i] >> (2*j)) & 0x3) << shift;
        }
    }
    if (r->n[9] == 0x3FFFFFUL && (r->n[8] & r->n[7] & r->n[6] & r->n[5] & r->n[4] & r->n[3] & r->n[2]) == 0x3FFFFFFUL && (r->n[1] + 0x40UL + ((r->n[0] + 0x3D1UL) >> 26)) > 0x3FFFFFFUL) {
        ret = -1;
        goto cleanup;
    }

cleanup:

    return( ret );
}

void mbedtls_fe_normalize_var(mbedtls_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    if (x) {
        t0 += 0x3D1UL; t1 += (x << 6);
        t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
        t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
        t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
        t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
        t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
        t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
        t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
        t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
        t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

        /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
        VERIFY_CHECK(t9 >> 22 == x);

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t9 &= 0x03FFFFFUL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;
}

void mbedtls_fe_normalize_weak(mbedtls_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;
}

// 4X64
// TODO: Add 8X32
unsigned int mbedtls_mpi_get_bits(mbedtls_mpi *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK((offset + count - 1) >> 6 == offset >> 6);
    return (a->p[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
}

// 4X64
// TODO: Add 8X32
unsigned int mbedtls_mpi_get_bits_var(mbedtls_mpi *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK(count < 32);
    VERIFY_CHECK(offset + count <= 256);
    if ((offset + count - 1) >> 6 == offset >> 6) {
        return mbedtls_mpi_get_bits(a, offset, count);
    } else {
        VERIFY_CHECK((offset >> 6) + 1 < 4);
        return ((a->p[offset >> 6] >> (offset & 0x3F)) | (a->p[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((uint64_t)1) << count) - 1);
    }
}

// TODO change to mbedtls_mpi_uint (64)
void mbedtls_fe_mul_int(mbedtls_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
    r->n[5] *= a;
    r->n[6] *= a;
    r->n[7] *= a;
    r->n[8] *= a;
    r->n[9] *= a;
}

int mbedtls_fe_normalizes_to_zero_var(mbedtls_fe *r) {
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t z0, z1;
    uint32_t x;

    t0 = r->n[0];
    t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    x = t9 >> 22;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0x3FFFFFFUL;
    z1 = z0 ^ 0x3D0UL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0UL) & (z1 != 0x3FFFFFFUL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];
    t4 = r->n[4];
    t5 = r->n[5];
    t6 = r->n[6];
    t7 = r->n[7];
    t8 = r->n[8];

    t9 &= 0x03FFFFFUL;
    t1 += (x << 6);

    t1 += (t0 >> 26);
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

void mbedtls_gej_set_ge(mbedtls_gej *r, const mbedtls_ge *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   mbedtls_fe_set_int(&r->z, 1);
}

void mbedtls_gej_double_var(mbedtls_gej *r, const mbedtls_gej *a, mbedtls_fe *rzr) {
    /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
     *
     * Note that there is an implementation described at
     *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
     * which trades a multiply for a square, but in practice this is actually slower,
     * mainly because it requires more normalizations.
     */
    mbedtls_fe t1,t2,t3,t4;
    /** For mbedtls, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    r->infinity = a->infinity;
    if (r->infinity) {
        if (rzr != NULL) {
            mbedtls_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        mbedtls_fe_normalize_weak(rzr);
        mbedtls_fe_mul_int(rzr, 2);
    }

    mbedtls_fe_mul(&r->z, &a->z, &a->y);
    mbedtls_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    mbedtls_fe_sqr(&t1, &a->x);
    mbedtls_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    mbedtls_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    mbedtls_fe_sqr(&t3, &a->y);
    mbedtls_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    mbedtls_fe_sqr(&t4, &t3);
    mbedtls_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    mbedtls_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    mbedtls_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    mbedtls_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    mbedtls_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    mbedtls_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    mbedtls_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    mbedtls_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    mbedtls_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    mbedtls_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    mbedtls_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

void mbedtls_ge_set_gej_zinv(mbedtls_ge *r, mbedtls_gej *a, const mbedtls_fe *zi) {
    mbedtls_fe zi2;
    mbedtls_fe zi3;
    mbedtls_fe_sqr(&zi2, zi);
    mbedtls_fe_mul(&zi3, &zi2, zi);
    mbedtls_fe_mul(&r->x, &a->x, &zi2);
    mbedtls_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

void mbedtls_gej_add_ge_var(mbedtls_gej *r, mbedtls_gej *a, mbedtls_ge *b, mbedtls_fe *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    mbedtls_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        mbedtls_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            mbedtls_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    mbedtls_fe_sqr(&z12, &a->z);
    u1 = a->x; mbedtls_fe_normalize_weak(&u1);
    mbedtls_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; mbedtls_fe_normalize_weak(&s1);
    mbedtls_fe_mul(&s2, &b->y, &z12); mbedtls_fe_mul(&s2, &s2, &a->z);
    mbedtls_fe_negate(&h, &u1, 1); mbedtls_fe_add(&h, &u2);
    mbedtls_fe_negate(&i, &s1, 1); mbedtls_fe_add(&i, &s2);
    if (mbedtls_fe_normalizes_to_zero_var(&h)) {
        if (mbedtls_fe_normalizes_to_zero_var(&i)) {
            mbedtls_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                mbedtls_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    mbedtls_fe_sqr(&i2, &i);
    mbedtls_fe_sqr(&h2, &h);
    mbedtls_fe_mul(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    mbedtls_fe_mul(&r->z, &a->z, &h);
    mbedtls_fe_mul(&t, &u1, &h2);
    r->x = t; mbedtls_fe_mul_int(&r->x, 2); mbedtls_fe_add(&r->x, &h3); mbedtls_fe_negate(&r->x, &r->x, 3); mbedtls_fe_add(&r->x, &i2);
    mbedtls_fe_negate(&r->y, &r->x, 5); mbedtls_fe_add(&r->y, &t); mbedtls_fe_mul(&r->y, &r->y, &i);
    mbedtls_fe_mul(&h3, &h3, &s1); mbedtls_fe_negate(&h3, &h3, 1);
    mbedtls_fe_add(&r->y, &h3);
}

void mbedtls_gej_add_zinv_var(mbedtls_gej *r, const mbedtls_gej *a, const mbedtls_ge *b, const mbedtls_fe *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    mbedtls_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (b->infinity) {
        *r = *a;
        return;
    }
    if (a->infinity) {
        mbedtls_fe bzinv2, bzinv3;
        r->infinity = b->infinity;
        mbedtls_fe_sqr(&bzinv2, bzinv);
        mbedtls_fe_mul(&bzinv3, &bzinv2, bzinv);
        mbedtls_fe_mul(&r->x, &b->x, &bzinv2);
        mbedtls_fe_mul(&r->y, &b->y, &bzinv3);
        mbedtls_fe_set_int(&r->z, 1);
        return;
    }
    r->infinity = 0;

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  mbedtls's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    mbedtls_fe_mul(&az, &a->z, bzinv);

    mbedtls_fe_sqr(&z12, &az);
    u1 = a->x; mbedtls_fe_normalize_weak(&u1);
    mbedtls_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; mbedtls_fe_normalize_weak(&s1);
    mbedtls_fe_mul(&s2, &b->y, &z12); mbedtls_fe_mul(&s2, &s2, &az);
    mbedtls_fe_negate(&h, &u1, 1); mbedtls_fe_add(&h, &u2);
    mbedtls_fe_negate(&i, &s1, 1); mbedtls_fe_add(&i, &s2);
    if (mbedtls_fe_normalizes_to_zero_var(&h)) {
        if (mbedtls_fe_normalizes_to_zero_var(&i)) {
            mbedtls_gej_double_var(r, a, NULL);
        } else {
            r->infinity = 1;
        }
        return;
    }
    mbedtls_fe_sqr(&i2, &i);
    mbedtls_fe_sqr(&h2, &h);
    mbedtls_fe_mul(&h3, &h, &h2);
    r->z = a->z; mbedtls_fe_mul(&r->z, &r->z, &h);
    mbedtls_fe_mul(&t, &u1, &h2);
    r->x = t; mbedtls_fe_mul_int(&r->x, 2); mbedtls_fe_add(&r->x, &h3); mbedtls_fe_negate(&r->x, &r->x, 3); mbedtls_fe_add(&r->x, &i2);
    mbedtls_fe_negate(&r->y, &r->x, 5); mbedtls_fe_add(&r->y, &t); mbedtls_fe_mul(&r->y, &r->y, &i);
    mbedtls_fe_mul(&h3, &h3, &s1); mbedtls_fe_negate(&h3, &h3, 1);
    mbedtls_fe_add(&r->y, &h3);
}

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
void mbedtls_ecmult_odd_multiples_table(int n, mbedtls_gej *prej, mbedtls_fe *zr, mbedtls_gej *a) {
    mbedtls_gej d;
    mbedtls_ge a_ge, d_ge;
    int i;

    VERIFY_CHECK(!a->infinity);
    mbedtls_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    mbedtls_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        mbedtls_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    mbedtls_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

void mbedtls_ge_globalz_set_table_gej(size_t len, mbedtls_ge *r, mbedtls_fe *globalz, const mbedtls_gej *a, const mbedtls_fe *zr) {
    size_t i = len - 1;
    mbedtls_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                mbedtls_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            mbedtls_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

/** Fill a table 'pre' with precomputed odd multiples of a.
 *
 *  There are two versions of this function:
 *  - secp256k1_ecmult_odd_multiples_table_globalz_windowa which brings its
 *    resulting point set to a single constant Z denominator, stores the X and Y
 *    coordinates as ge_storage points in pre, and stores the global Z in rz.
 *    It only operates on tables sized for WINDOW_A wnaf multiples.
 *  - secp256k1_ecmult_odd_multiples_table_storage_var, which converts its
 *    resulting point set to actually affine points, and stores those in pre.
 *    It operates on tables of any size, but uses heap-allocated temporaries.
 *
 *  To compute a*P + b*G, we compute a table for P using the first function,
 *  and for G using the second (which requires an inverse, but it only needs to
 *  happen once).
 */
void mbedtls_ecmult_odd_multiples_table_globalz_windowa(mbedtls_ecp_group *grp, mbedtls_ge *pre, mbedtls_fe *globalz, mbedtls_gej *a, int window_size) {
    mbedtls_gej prej[ECMULT_TABLE_SIZE(window_size)];
    mbedtls_fe zr[ECMULT_TABLE_SIZE(window_size)];

    /* Compute the odd multiples in Jacobian form. */
    mbedtls_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(window_size), &prej, &zr, a);
    /* Bring them to the same Z denominator. */
    mbedtls_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(window_size), pre, globalz, &prej, &zr);
}

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
int mbedtls_ecmult_wnaf(mbedtls_ecp_group *grp, int *wnaf, int len, mbedtls_mpi *a, int w) {
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;
    mbedtls_mpi s, sn;
    mbedtls_mpi_init(&s);mbedtls_mpi_init(&sn);

    VERIFY_CHECK(wnaf != NULL);
    VERIFY_CHECK(0 <= len && len <= 256);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(2 <= w && w <= 31);

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    if (mbedtls_mpi_get_bits(a, 255, 1)) {
        mbedtls_mpi_sub_mpi( &sn, &grp->N, a );
        mbedtls_mpi_mod_mpi( &s, &sn, &grp->N );
        sign = -1;
    } else {
        mbedtls_mpi_copy(&s, a);
    }

    while ( bit < len ) {
        int now;
        int word;
        if ( mbedtls_mpi_get_bits( &s, bit, 1 ) == (unsigned int) carry ) {
            bit++;
            continue;
        }

        now = w;
        if ( now > len - bit ) {
            now = len - bit;
        }

        word = mbedtls_mpi_get_bits_var( &s, bit, now ) + carry;

        carry = ( word >> ( w - 1 ) ) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
    mbedtls_mpi_free(&s);mbedtls_mpi_free(&sn);
    return last_set_bit + 1;
}

void mbedtls_fe_clear(mbedtls_fe *a) {
    int i;
    for (i=0; i<10; i++) {
        a->n[i] = 0;
    }
}

void mbedtls_gej_set_infinity(mbedtls_gej *r) {
    r->infinity = 1;
    mbedtls_fe_clear(&r->x);
    mbedtls_fe_clear(&r->y);
    mbedtls_fe_clear(&r->z);
}


void mbedtls_ge_neg(mbedtls_ge *r, const mbedtls_ge *a) {
    *r = *a;
    mbedtls_fe_normalize_weak(&r->y);
    mbedtls_fe_negate(&r->y, &r->y, 1);
}

void mbedtls_fe_from_storage(mbedtls_fe *r, const mbedtls_fe_storage *a) {
    r->n[0] = a->n[0] & 0x3FFFFFFUL;
    r->n[1] = a->n[0] >> 26 | ((a->n[1] << 6) & 0x3FFFFFFUL);
    r->n[2] = a->n[1] >> 20 | ((a->n[2] << 12) & 0x3FFFFFFUL);
    r->n[3] = a->n[2] >> 14 | ((a->n[3] << 18) & 0x3FFFFFFUL);
    r->n[4] = a->n[3] >> 8 | ((a->n[4] << 24) & 0x3FFFFFFUL);
    r->n[5] = (a->n[4] >> 2) & 0x3FFFFFFUL;
    r->n[6] = a->n[4] >> 28 | ((a->n[5] << 4) & 0x3FFFFFFUL);
    r->n[7] = a->n[5] >> 22 | ((a->n[6] << 10) & 0x3FFFFFFUL);
    r->n[8] = a->n[6] >> 16 | ((a->n[7] << 16) & 0x3FFFFFFUL);
    r->n[9] = a->n[7] >> 10;
}

void mbedtls_fe_to_storage(mbedtls_fe_storage *r, const mbedtls_fe *a) {
    r->n[0] = a->n[0] | a->n[1] << 26;
    r->n[1] = a->n[1] >> 6 | a->n[2] << 20;
    r->n[2] = a->n[2] >> 12 | a->n[3] << 14;
    r->n[3] = a->n[3] >> 18 | a->n[4] << 8;
    r->n[4] = a->n[4] >> 24 | a->n[5] << 2 | a->n[6] << 28;
    r->n[5] = a->n[6] >> 4 | a->n[7] << 22;
    r->n[6] = a->n[7] >> 10 | a->n[8] << 16;
    r->n[7] = a->n[8] >> 16 | a->n[9] << 10;
}

void mbedtls_fe_normalize(mbedtls_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
    VERIFY_CHECK(t9 >> 22 == x);

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t9 &= 0x03FFFFFUL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;
}

void mbedtls_ge_from_storage(mbedtls_ge *r, const mbedtls_ge_storage *a) {
    mbedtls_fe_from_storage(&r->x, &a->x);
    mbedtls_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

void mbedtls_ge_to_storage(mbedtls_ge_storage *r, const mbedtls_ge *a) {
    mbedtls_fe x, y;
    VERIFY_CHECK(!a->infinity);
    x = a->x;
    mbedtls_fe_normalize(&x);
    y = a->y;
    mbedtls_fe_normalize(&y);
    mbedtls_fe_to_storage(&r->x, &x);
    mbedtls_fe_to_storage(&r->y, &y);
}

void mbedtls_fe_inv(mbedtls_fe *r, const mbedtls_fe *a) {
    mbedtls_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    mbedtls_fe_sqr(&x2, a);
    mbedtls_fe_mul(&x2, &x2, a);

    mbedtls_fe_sqr(&x3, &x2);
    mbedtls_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x6, &x6);
    }
    mbedtls_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x9, &x9);
    }
    mbedtls_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        mbedtls_fe_sqr(&x11, &x11);
    }
    mbedtls_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        mbedtls_fe_sqr(&x22, &x22);
    }
    mbedtls_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        mbedtls_fe_sqr(&x44, &x44);
    }
    mbedtls_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        mbedtls_fe_sqr(&x88, &x88);
    }
    mbedtls_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        mbedtls_fe_sqr(&x176, &x176);
    }
    mbedtls_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        mbedtls_fe_sqr(&x220, &x220);
    }
    mbedtls_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&x223, &x223);
    }
    mbedtls_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        mbedtls_fe_sqr(&t1, &t1);
    }
    mbedtls_fe_mul(r, a, &t1);
}

void mbedtls_ge_set_table_gej_var(mbedtls_ge *r, const mbedtls_gej *a, const mbedtls_fe *zr, size_t len) {
    size_t i = len - 1;
    mbedtls_fe zi;

    if (len > 0) {
        /* Compute the inverse of the last z coordinate, and use it to compute the last affine output. */
        mbedtls_fe_inv(&zi, &a[i].z);
        mbedtls_ge_set_gej_zinv(&r[i], &a[i], &zi);

        /* Work out way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            mbedtls_fe_mul(&zi, &zi, &zr[i]);
            i--;
            mbedtls_ge_set_gej_zinv(&r[i], &a[i], &zi);
        }
    }
}

int mbedtls_ecmult_odd_multiples_table_storage_var(int n, mbedtls_ge_storage *pre, mbedtls_gej *a) {
    int ret;
    mbedtls_gej *prej = (mbedtls_gej*) malloc(sizeof(mbedtls_gej) * n);
    mbedtls_ge *prea = (mbedtls_ge*) malloc(sizeof(mbedtls_ge) * n);
    mbedtls_fe *zr = (mbedtls_fe*) malloc(sizeof(mbedtls_fe) * n);
    ECDSA_VALIDATE_RET( prej != NULL );
    ECDSA_VALIDATE_RET( prea != NULL );
    ECDSA_VALIDATE_RET( zr != NULL );
    int i;

    /* Compute the odd multiples in Jacobian form. */
    mbedtls_ecmult_odd_multiples_table(n, prej, zr, a);
    /* Convert them in batch to affine coordinates. */
    mbedtls_ge_set_table_gej_var(prea, prej, zr, n);
    /* Convert them to compact storage form. */
    for (i = 0; i < n; i++) {
        mbedtls_ge_to_storage(&pre[i], &prea[i]);
    }

    free(prea);
    free(prej);
    free(zr);

cleanup:

    return( ret );
}

void mbedtls_ecmult(mbedtls_ecp_group *grp, mbedtls_ge_storage *pre_g, mbedtls_gej *r, mbedtls_gej *a, mbedtls_mpi *na, mbedtls_mpi *ng, int window_size_a, int window_size_g) {
    mbedtls_ge pre_a[ECMULT_TABLE_SIZE(window_size_a)];
    mbedtls_ge tmpa;
    mbedtls_fe Z;
    int wnaf_na[256];
    int bits_na;
    int wnaf_ng[256];
    int bits_ng;
    int i;
    int bits;

    /* build wnaf representation for na. */
    bits_na = mbedtls_ecmult_wnaf(grp, &wnaf_na, 256, na, window_size_a);
    bits = bits_na;

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     * The exception is the precomputed G table points, which are actually
     * affine. Compared to the base used for other points, they have a Z ratio
     * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
     * isomorphism to efficiently add with a known Z inverse.
     */
    mbedtls_ecmult_odd_multiples_table_globalz_windowa(grp, &pre_a, &Z, a, window_size_a);

    int total = ECMULT_TABLE_SIZE(window_size_a);

    bits_ng = mbedtls_ecmult_wnaf(grp, &wnaf_ng, 256, ng, window_size_g);
    if (bits_ng > bits) {
        bits = bits_ng;
    }

    mbedtls_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        mbedtls_gej_double_var(r, r, NULL);
        if (i < bits_na && (n = wnaf_na[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, window_size_a);
            mbedtls_gej_add_ge_var(r, r, &tmpa, NULL);
        }
        if (i < bits_ng && (n = wnaf_ng[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, pre_g, n, window_size_g);
            mbedtls_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
    }

    if (!r->infinity) {
        mbedtls_fe_mul(&r->z, &r->z, &Z);
    }
}

void mbedtls_fe_inv_var(mbedtls_fe *r, const mbedtls_fe *a) {
    mbedtls_fe_inv(r, a);
}

void mbedtls_ge_set_gej_var(mbedtls_ge *r, mbedtls_gej *a) {
    mbedtls_fe z2, z3;
    r->infinity = a->infinity;
    if (a->infinity) {
        return;
    }
    mbedtls_fe_inv_var(&a->z, &a->z);
    mbedtls_fe_sqr(&z2, &a->z);
    mbedtls_fe_mul(&z3, &a->z, &z2);
    mbedtls_fe_mul(&a->x, &a->x, &z2);
    mbedtls_fe_mul(&a->y, &a->y, &z3);
    mbedtls_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

/*
 * Recover ECDSA public key from ECDSA signature of a hashed message
 * Should initialize mbedtls_ecp_point first
 *
 * TODO:
 * Only support secp256k1?
 * Should we add int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, mbedtls_ecdsa_restart_ctx *rs_ctx?
 * initialize pmo when load group
 * WNAF Notation
 * MOVE p mod n to grp
 * Recovery process:
 * Use mbedtls ecp defined type
 * if set blen as size_t, the value will be wrong
 */
int ecdsa_sig_recover( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s, int recid,
                const unsigned char *pubkey_buf, const unsigned char *buf, int blen,
                mbedtls_ge_storage *pre_g, int window_size_a, int window_size_g )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( pubkey     != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
    ECDSA_VALIDATE_RET( mbedtls_mpi_cmp_int( r, 0 ) == 0 || mbedtls_mpi_cmp_int( s, 0 ) == 0 );
    ECDSA_VALIDATE_RET( recid >=0 && recid < 4 );
    ECDSA_VALIDATE_RET( pre_g != NULL );

    int ret;
    // mbedtls_ecp_point fx;
    // mbedtls_ecp_point qj;
    mbedtls_gej xj;
    mbedtls_gej qj;
    mbedtls_gej gj;
    mbedtls_ge pubkey;
    mbedtls_ge_storage ss;
    mbedtls_fe fe;
    mbedtls_fe fy;
    mbedtls_fe fe_order;
    mbedtls_mpi pmo, m, rn, u1, u2, rnm, mn, u1n, sn;
    // mbedtls_ecp_point_init(&fx);mbedtls_ecp_point_init(&qj);
    mbedtls_mpi_init(&pmo);mbedtls_mpi_init(&m);mbedtls_mpi_init(&rn);mbedtls_mpi_init(&u1);mbedtls_mpi_init(&u2);
    mbedtls_mpi_init(&rnm);mbedtls_mpi_init(&mn);mbedtls_mpi_init(&sn);
    // TODO: change hardcode parameter
    // MBEDTLS_MPI_CHK( ecp_mpi_load( &pmo, &secp256k1_p_minus_order, sizeof( secp256k1_p_minus_order ) ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &pmo, 16, "014551231950B75FC4402DA1722FC9BAEE" ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&m, buf, blen) );
    MBEDTLS_MPI_CHK( mbedtls_fe_set_b32( &fe, r ) );

    if ( recid & 2 ) {
        if (mbedtls_mpi_cmp_mpi(r, &pmo) >= 0) {
            return -1;
        }
        MBEDTLS_MPI_CHK( mbedtls_fe_set_b32( &fe_order, &grp->N ) );
        mbedtls_fe_add( &fe, &fe_order );
    }
    // generate point from the x
    MBEDTLS_MPI_CHK( mbedtls_set_xo_var( &fe, &fy, recid & 1 ) );
    // MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &fx.Z, &fx.Z, 1 ) );
    // MBEDTLS_MPI_CHK( mbedtls_fe_to_mpi( &fe, &fx.X ) );
    // MBEDTLS_MPI_CHK( mbedtls_fe_to_mpi( &fy, &fx.Y ) );
    xj.x = fe;
    xj.y = fy;
    xj.infinity = 0;
    mbedtls_fe_set_int(&xj.z, 1);

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &rn, r, &grp->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mn, &grp->N, &m ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &rnm, &mn, &rn ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &u1, &rnm, &grp->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &sn, s, &rn ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &u2, &sn, &grp->N ) );

    mbedtls_ecmult(grp, pre_g, &qj, &xj, &u2, &u1, window_size_a, window_size_g);
    mbedtls_ge_set_gej_var(&pubkey, &qj);
    mbedtls_fe_normalize_var(&pubkey.x);
    mbedtls_fe_normalize_var(&pubkey.y);
    memset(pubkey_buf, 0x04, 1);
    mbedtls_fe_get_b32(pubkey_buf+1, &pubkey.x);
    mbedtls_fe_get_b32(pubkey_buf+33, &pubkey.y);
    // mbedtls_fe_to_mpi(&pubkey.x, &Q->X);
    // mbedtls_fe_to_mpi(&pubkey.y, &Q->Y);
    ret = qj.infinity;

cleanup:

    // mbedtls_ecp_point_free(&fx);mbedtls_ecp_point_init(&qj);
    mbedtls_mpi_free(&pmo);mbedtls_mpi_free(&m);mbedtls_mpi_free(&rn);mbedtls_mpi_free(&u1);mbedtls_mpi_free(&u2);
    mbedtls_mpi_free(&rnm);mbedtls_mpi_free(&mn);mbedtls_mpi_free(&sn);

    return( ret );
}

/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int ecdsa_sign_recoverable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s, const mbedtls_mpi *d,
                int* recid, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( mbedtls_mpi_cmp_int( d, 1 ) < 0 || mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e ); mbedtls_mpi_init( &t );

    ECDSA_RS_ENTER( sig );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->sig != NULL )
    {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;

        /* jump to current step */
        if( rs_ctx->sig->state == ecdsa_sig_mul )
            goto mul;
        if( rs_ctx->sig->state == ecdsa_sig_modn )
            goto modn;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    *p_sign_tries = 0;
    do
    {
        if( *p_sign_tries++ > 10 )
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do
        {
            if( *p_key_tries++ > 10 )
            {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, pk, f_rng, p_rng ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
            if( rs_ctx != NULL && rs_ctx->sig != NULL )
                rs_ctx->sig->state = ecdsa_sig_mul;

mul:
#endif
            MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, &R, pk, &grp->G,
                                                  f_rng, p_rng, ECDSA_RS_ECP ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( pr, &R.X, &grp->N ) );
        }
        while( mbedtls_mpi_cmp_int( pr, 0 ) == 0 );

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && rs_ctx->sig != NULL )
            rs_ctx->sig->state = ecdsa_sig_modn;

modn:
#endif
        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET( MBEDTLS_ECP_OPS_INV + 4 );

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, &t, f_rng, p_rng ) );

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( s, pr, d ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &e, &e, s ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &e, &e, &t ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( pk, pk, &t ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( s, pk, &grp->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( s, s, &e ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( s, s, &grp->N ) );
    }
    while( mbedtls_mpi_cmp_int( s, 0 ) == 0 );

    // caculate recovery id
    int rec = ( ( mbedtls_mpi_is_odd(&R.Y) <= 0 ) ? 0: 1 ) | ( ( mbedtls_mpi_cmp_mpi(pr, &R.X) != 0) ? 2 : 1 );
    memcpy(recid, &rec, sizeof(rec));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->sig != NULL )
        mbedtls_mpi_copy( r, pr );
#endif

cleanup:
    mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &k ); mbedtls_mpi_free( &e ); mbedtls_mpi_free( &t );

    ECDSA_RS_LEAVE( sig );

    return( ret );
}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign_recoverable( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, int *recid, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( recid != NULL );
    ECDSA_VALIDATE_RET( f_rng != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_recoverable( grp, r, s, d, recid, buf, blen,
                                    f_rng, p_rng, NULL ) );
}

/*
 * Deterministic signature wrapper
 */
int mbedtls_ecdsa_sign_det_recoverable( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, int *recid, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( recid != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    int ret;
    mbedtls_hmac_drbg_context rng_ctx;
    mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = ( grp->nbits + 7 ) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;
    mbedtls_ecdsa_restart_ctx *rs_ctx;

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_mpi_init( &h );
    mbedtls_hmac_drbg_init( &rng_ctx );

    ECDSA_RS_ENTER( det );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->det != NULL )
    {
        /* redirect to our context */
        p_rng = &rs_ctx->det->rng_ctx;

        /* jump to current step */
        if( rs_ctx->det->state == ecdsa_det_sign )
            goto sign;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( d, data, grp_len ) );
    MBEDTLS_MPI_CHK( derive_mpi( grp, &h, buf, blen ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &h, data + grp_len, grp_len ) );
    mbedtls_hmac_drbg_seed_buf( p_rng, md_info, data, 2 * grp_len );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->det != NULL )
        rs_ctx->det->state = ecdsa_det_sign;

sign:
#endif
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    ret = mbedtls_ecdsa_sign_recoverable( grp, r, s, d, recid, buf, blen,
                              mbedtls_hmac_drbg_random, p_rng );
#else
    ret = ecdsa_sign_recoverable( grp, r, s, d, recid, buf, blen,
                      mbedtls_hmac_drbg_random, p_rng, rs_ctx );
#endif /* MBEDTLS_ECDSA_SIGN_ALT */

cleanup:
    mbedtls_hmac_drbg_free( &rng_ctx );
    mbedtls_mpi_free( &h );

    ECDSA_RS_LEAVE( det );

    return( ret );
}
#endif /* MBEDTLS_ECP_RECOVERABLE */

/*
 * Set context from an mbedtls_ecp_keypair
 */
int mbedtls_ecdsa_from_keypair( mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key )
{
    int ret;
    ECDSA_VALIDATE_RET( ctx != NULL );
    ECDSA_VALIDATE_RET( key != NULL );

    if( ( ret = mbedtls_ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &ctx->d, &key->d ) ) != 0 ||
        ( ret = mbedtls_ecp_copy( &ctx->Q, &key->Q ) ) != 0 )
    {
        mbedtls_ecdsa_free( ctx );
    }

    return( ret );
}

/*
 * Initialize context
 */
void mbedtls_ecdsa_init( mbedtls_ecdsa_context *ctx )
{
    ECDSA_VALIDATE( ctx != NULL );

    mbedtls_ecp_keypair_init( ctx );
}

/*
 * Free context
 */
void mbedtls_ecdsa_free( mbedtls_ecdsa_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_ecp_keypair_free( ctx );
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void mbedtls_ecdsa_restart_init( mbedtls_ecdsa_restart_ctx *ctx )
{
    ECDSA_VALIDATE( ctx != NULL );

    mbedtls_ecp_restart_init( &ctx->ecp );

    ctx->ver = NULL;
    ctx->sig = NULL;
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    ctx->det = NULL;
#endif
}

/*
 * Free the components of a restart context
 */
void mbedtls_ecdsa_restart_free( mbedtls_ecdsa_restart_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_ecp_restart_free( &ctx->ecp );

    ecdsa_restart_ver_free( ctx->ver );
    mbedtls_free( ctx->ver );
    ctx->ver = NULL;

    ecdsa_restart_sig_free( ctx->sig );
    mbedtls_free( ctx->sig );
    ctx->sig = NULL;

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    ecdsa_restart_det_free( ctx->det );
    mbedtls_free( ctx->det );
    ctx->det = NULL;
#endif
}
#endif /* MBEDTLS_ECP_RESTARTABLE */

#endif /* MBEDTLS_ECDSA_C */
