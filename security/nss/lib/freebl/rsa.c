/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 *
 */

/*
 * RSA key generation, public key op, private key op.
 *
 * $Id$
 */

#include "secerr.h"

#include "prclist.h"
#include "nssilock.h"
#include "prinit.h"
#include "blapi.h"
#include "mpi.h"
#include "mpprime.h"
#include "mplogic.h"
#include "secmpi.h"
#include "secitem.h"

/*
** RSABlindingParamsStr
**
** For discussion of Paul Kocher's timing attack against an RSA private key
** operation, see http://www.cryptography.com/timingattack/paper.html.  The 
** countermeasure to this attack, known as blinding, is also discussed in 
** the Handbook of Applied Cryptography, 11.118-11.119.
*/
struct RSABlindingParamsStr
{
    /* Blinding-specific parameters */
    PRCList   link;                  /* link to list of structs            */
    SECItem   modulus;               /* list element "key"                 */
    mp_int    f, g;                  /* Blinding parameters                */
    int       counter;               /* number of remaining uses of (f, g) */
};

/*
** RSABlindingParamsListStr
**
** List of key-specific blinding params.  The arena holds the volatile pool
** of memory for each entry and the list itself.  The lock is for list
** operations, in this case insertions and iterations, as well as control
** of the counter for each set of blinding parameters.
*/
struct RSABlindingParamsListStr
{
    PZLock  *lock;   /* Lock for the list   */
    PRCList  head;   /* Pointer to the list */
};

/*
** The master blinding params list.
*/
static struct RSABlindingParamsListStr blindingParamsList = { 0 };

/* Number of times to reuse (f, g).  Suggested by Paul Kocher */
#define RSA_BLINDING_PARAMS_MAX_REUSE 50

/* Global, allows optional use of blinding.  On by default. */
/* Cannot be changed at the moment, due to thread-safety issues. */
static PRBool nssRSAUseBlinding = PR_TRUE;

static SECStatus
rsa_keygen_from_primes(mp_int *p, mp_int *q, mp_int *e, RSAPrivateKey *key,
                       unsigned int keySizeInBits)
{
    mp_int n, d, phi;
    mp_int psub1, qsub1, tmp;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    MP_DIGITS(&n)     = 0;
    MP_DIGITS(&d)     = 0;
    MP_DIGITS(&phi)   = 0;
    MP_DIGITS(&psub1) = 0;
    MP_DIGITS(&qsub1) = 0;
    MP_DIGITS(&tmp)   = 0;
    CHECK_MPI_OK( mp_init(&n)     );
    CHECK_MPI_OK( mp_init(&d)     );
    CHECK_MPI_OK( mp_init(&phi)   );
    CHECK_MPI_OK( mp_init(&psub1) );
    CHECK_MPI_OK( mp_init(&qsub1) );
    CHECK_MPI_OK( mp_init(&tmp)   );
    /* 1.  Compute n = p*q */
    CHECK_MPI_OK( mp_mul(p, q, &n) );
    /*     verify that the modulus has the desired number of bits */
    if ((unsigned)mpl_significant_bits(&n) != keySizeInBits) {
	PORT_SetError(SEC_ERROR_NEED_RANDOM);
	rv = SECFailure;
	goto cleanup;
    }
    /* 2.  Compute phi = (p-1)*(q-1) */
    CHECK_MPI_OK( mp_sub_d(p, 1, &psub1) );
    CHECK_MPI_OK( mp_sub_d(q, 1, &qsub1) );
    CHECK_MPI_OK( mp_mul(&psub1, &qsub1, &phi) );
    /* 3.  Compute d = e**-1 mod(phi) */
    err = mp_invmod(e, &phi, &d);
    /*     Verify that phi(n) and e have no common divisors */
    if (err != MP_OKAY) {
	if (err == MP_UNDEF) {
	    PORT_SetError(SEC_ERROR_NEED_RANDOM);
	    err = MP_OKAY; /* to keep PORT_SetError from being called again */
	    rv = SECFailure;
	}
	goto cleanup;
    }
    MPINT_TO_SECITEM(&n, &key->modulus, key->arena);
    MPINT_TO_SECITEM(&d, &key->privateExponent, key->arena);
    /* 4.  Compute exponent1 = d mod (p-1) */
    CHECK_MPI_OK( mp_mod(&d, &psub1, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->exponent1, key->arena);
    /* 5.  Compute exponent2 = d mod (q-1) */
    CHECK_MPI_OK( mp_mod(&d, &qsub1, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->exponent2, key->arena);
    /* 6.  Compute coefficient = q**-1 mod p */
    CHECK_MPI_OK( mp_invmod(q, p, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->coefficient, key->arena);
cleanup:
    mp_clear(&n);
    mp_clear(&d);
    mp_clear(&phi);
    mp_clear(&psub1);
    mp_clear(&qsub1);
    mp_clear(&tmp);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

/*
** Generate and return a new RSA public and private key.
**	Both keys are encoded in a single RSAPrivateKey structure.
**	"cx" is the random number generator context
**	"keySizeInBits" is the size of the key to be generated, in bits.
**	   512, 1024, etc.
**	"publicExponent" when not NULL is a pointer to some data that
**	   represents the public exponent to use. The data is a byte
**	   encoded integer, in "big endian" order.
*/
RSAPrivateKey *
RSA_NewKey(int keySizeInBits, SECItem *publicExponent)
{
    unsigned char *pb = NULL, *qb = NULL;
    unsigned int primeLen;
    unsigned long counter;
    mp_int p, q, e;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    int prerr = 0;
    RSAPrivateKey *key = NULL;
    PRArenaPool *arena = NULL;
    /* Require key size to be a multiple of 16 bits. */
    if (!publicExponent || keySizeInBits % 16 != 0) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return NULL;
    }
    /* length of primes p and q (in bytes) */
    primeLen = keySizeInBits / (2 * BITS_PER_BYTE);
    MP_DIGITS(&p) = 0;
    MP_DIGITS(&q) = 0;
    MP_DIGITS(&e) = 0;
    CHECK_MPI_OK( mp_init(&p) );
    CHECK_MPI_OK( mp_init(&q) );
    CHECK_MPI_OK( mp_init(&e) );
    /* 1. Allocate arena & key */
    arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if (!arena) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	return NULL;
    }
    key = (RSAPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(RSAPrivateKey));
    if (!key) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	PORT_FreeArena(arena, PR_TRUE);
	return NULL;
    }
    key->arena = arena;
    /* 2.  Set the version number (PKCS1 v1.5 says it should be zero) */
    SECITEM_AllocItem(arena, &key->version, 1);
    key->version.data[0] = 0;
    /* 3.  Set the public exponent */
    SECITEM_CopyItem(arena, &key->publicExponent, publicExponent);
    SECITEM_TO_MPINT(*publicExponent, &e);
    /* 4.  Generate primes p and q */
    pb = PORT_Alloc(primeLen);
    qb = PORT_Alloc(primeLen);
    if (!pb || !qb) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	goto cleanup;
    }
    do {
	PORT_SetError(0);
	CHECK_SEC_OK( RNG_GenerateGlobalRandomBytes(pb, primeLen) );
	CHECK_SEC_OK( RNG_GenerateGlobalRandomBytes(qb, primeLen) );
	pb[0]          |= 0xC0; /* set two high-order bits */
	pb[primeLen-1] |= 0x01; /* set low-order bit       */
	qb[0]          |= 0xC0; /* set two high-order bits */
	qb[primeLen-1] |= 0x01; /* set low-order bit       */
	CHECK_MPI_OK( mp_read_unsigned_octets(&p, pb, primeLen) );
	CHECK_MPI_OK( mp_read_unsigned_octets(&q, qb, primeLen) );
	CHECK_MPI_OK( mpp_make_prime(&p, primeLen * 8, PR_FALSE, &counter) );
	CHECK_MPI_OK( mpp_make_prime(&q, primeLen * 8, PR_FALSE, &counter) );
	if (mp_cmp(&p, &q) < 0)
	    mp_exch(&p, &q);
	rv = rsa_keygen_from_primes(&p, &q, &e, key, keySizeInBits);
	if (rv == SECSuccess)
	    break; /* generated two good primes */
	prerr = PORT_GetError();
    } while (prerr == SEC_ERROR_NEED_RANDOM); /* loop until have primes */
    MPINT_TO_SECITEM(&p, &key->prime1, arena);
    MPINT_TO_SECITEM(&q, &key->prime2, arena);
cleanup:
    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&e);
    if (pb)
	PORT_ZFree(pb, primeLen);
    if (qb)
	PORT_ZFree(qb, primeLen);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    if (rv && arena) {
	PORT_FreeArena(arena, PR_TRUE);
	key = NULL;
    }
    return key;
}

static unsigned int
rsa_modulusLen(SECItem *modulus)
{
    unsigned char byteZero = modulus->data[0];
    unsigned int modLen = modulus->len - !byteZero;
    return modLen;
}

/*
** Perform a raw public-key operation 
**	Length of input and output buffers are equal to key's modulus len.
*/
SECStatus 
RSA_PublicKeyOp(RSAPublicKey  *key, 
                unsigned char *output, 
                const unsigned char *input)
{
    unsigned int modLen;
    mp_int n, e, m, c;
    mp_err err   = MP_OKAY;
    SECStatus rv = SECSuccess;
    if (!key || !output || !input) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }
    MP_DIGITS(&n) = 0;
    MP_DIGITS(&e) = 0;
    MP_DIGITS(&m) = 0;
    MP_DIGITS(&c) = 0;
    CHECK_MPI_OK( mp_init(&n) );
    CHECK_MPI_OK( mp_init(&e) );
    CHECK_MPI_OK( mp_init(&m) );
    CHECK_MPI_OK( mp_init(&c) );
    modLen = rsa_modulusLen(&key->modulus);
    /* 1.  Obtain public key (n, e) */
    SECITEM_TO_MPINT(key->modulus, &n);
    SECITEM_TO_MPINT(key->publicExponent, &e);
    /* 2.  Represent message as integer in range [0..n-1] */
    CHECK_MPI_OK( mp_read_unsigned_octets(&m, input, modLen) );
    /* 3.  Compute c = m**e mod n */
#ifdef USE_MPI_EXPT_D
    /* XXX see which is faster */
    if (MP_USED(&e) == 1) {
	CHECK_MPI_OK( mp_exptmod_d(&m, MP_DIGIT(&e, 0), &n, &c) );
    } else
#endif
    CHECK_MPI_OK( mp_exptmod(&m, &e, &n, &c) );
    /* 4.  result c is ciphertext */
    err = mp_to_fixlen_octets(&c, output, modLen);
    if (err >= 0) err = MP_OKAY;
cleanup:
    mp_clear(&n);
    mp_clear(&e);
    mp_clear(&m);
    mp_clear(&c);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

/*
**  RSA Private key operation (no CRT).
*/
static SECStatus 
rsa_PrivateKeyOp(RSAPrivateKey *key, mp_int *m, mp_int *c, mp_int *n,
                 unsigned int modLen)
{
    mp_int d;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    MP_DIGITS(&d) = 0;
    CHECK_MPI_OK( mp_init(&d) );
    SECITEM_TO_MPINT(key->privateExponent, &d);
    /* 1. m = c**d mod n */
    CHECK_MPI_OK( mp_exptmod(c, &d, n, m) );
cleanup:
    mp_clear(&d);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

/*
**  RSA Private key operation using CRT.
*/
static SECStatus 
rsa_PrivateKeyOpCRT(RSAPrivateKey *key, mp_int *m, mp_int *c,
                    unsigned int modLen)
{
    mp_int p, q, d_p, d_q, qInv;
    mp_int m1, m2, b2, h, ctmp;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    MP_DIGITS(&p)    = 0;
    MP_DIGITS(&q)    = 0;
    MP_DIGITS(&d_p)  = 0;
    MP_DIGITS(&d_q)  = 0;
    MP_DIGITS(&qInv) = 0;
    MP_DIGITS(&m1)   = 0;
    MP_DIGITS(&m2)   = 0;
    MP_DIGITS(&b2)   = 0;
    MP_DIGITS(&h)    = 0;
    MP_DIGITS(&ctmp) = 0;
    CHECK_MPI_OK( mp_init(&p)    );
    CHECK_MPI_OK( mp_init(&q)    );
    CHECK_MPI_OK( mp_init(&d_p)  );
    CHECK_MPI_OK( mp_init(&d_q)  );
    CHECK_MPI_OK( mp_init(&qInv) );
    CHECK_MPI_OK( mp_init(&m1)   );
    CHECK_MPI_OK( mp_init(&m2)   );
    CHECK_MPI_OK( mp_init(&b2)   );
    CHECK_MPI_OK( mp_init(&h)    );
    CHECK_MPI_OK( mp_init(&ctmp) );
    /* copy private key parameters into mp integers */
    SECITEM_TO_MPINT(key->prime1,      &p);    /* p */
    SECITEM_TO_MPINT(key->prime2,      &q);    /* q */
    SECITEM_TO_MPINT(key->exponent1,   &d_p);  /* d_p  = d mod (p-1) */
    SECITEM_TO_MPINT(key->exponent2,   &d_q);  /* d_p  = d mod (q-1) */
    SECITEM_TO_MPINT(key->coefficient, &qInv); /* qInv = q**-1 mod p */
    /* 1. m1 = c**d_p mod p */
    CHECK_MPI_OK( mp_mod(c, &p, &ctmp) );
    CHECK_MPI_OK( mp_exptmod(&ctmp, &d_p, &p, &m1) );
    /* 2. m2 = c**d_q mod q */
    CHECK_MPI_OK( mp_mod(c, &q, &ctmp) );
    CHECK_MPI_OK( mp_exptmod(&ctmp, &d_q, &q, &m2) );
    /* 3.  h = (m1 - m2) * qInv mod p */
    CHECK_MPI_OK( mp_submod(&m1, &m2, &p, &h) );
    CHECK_MPI_OK( mp_mulmod(&h, &qInv, &p, &h)  );
    /* 4.  m = m2 + h * q */
    CHECK_MPI_OK( mp_mul(&h, &q, m) );
    CHECK_MPI_OK( mp_add(m, &m2, m) );
cleanup:
    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&d_p);
    mp_clear(&d_q);
    mp_clear(&qInv);
    mp_clear(&m1);
    mp_clear(&m2);
    mp_clear(&b2);
    mp_clear(&h);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

static PRCallOnceType coBPInit = { 0, 0, 0 };
static PRStatus 
init_blinding_params_list(void)
{
    blindingParamsList.lock = PZ_NewLock(nssILockOther);
    if (!blindingParamsList.lock) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	return PR_FAILURE;
    }
    PR_INIT_CLIST(&blindingParamsList.head);
    return PR_SUCCESS;
}

static SECStatus
generate_blinding_params(struct RSABlindingParamsStr *rsabp, 
                         RSAPrivateKey *key, mp_int *n, unsigned int modLen)
{
    SECStatus rv = SECSuccess;
    mp_int e, k;
    mp_err err = MP_OKAY;
    unsigned char *kb = NULL;
    MP_DIGITS(&e) = 0;
    MP_DIGITS(&k) = 0;
    CHECK_MPI_OK( mp_init(&e) );
    CHECK_MPI_OK( mp_init(&k) );
    SECITEM_TO_MPINT(key->publicExponent, &e);
    /* generate random k < n */
    kb = PORT_Alloc(modLen);
    if (!kb) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	goto cleanup;
    }
    CHECK_SEC_OK( RNG_GenerateGlobalRandomBytes(kb, modLen) );
    CHECK_MPI_OK( mp_read_unsigned_octets(&k, kb, modLen) );
    /* k < n */
    CHECK_MPI_OK( mp_mod(&k, n, &k) );
    /* f = k**e mod n */
    CHECK_MPI_OK( mp_exptmod(&k, &e, n, &rsabp->f) );
    /* g = k**-1 mod n */
    CHECK_MPI_OK( mp_invmod(&k, n, &rsabp->g) );
    /* Initialize the counter for this (f, g) */
    rsabp->counter = RSA_BLINDING_PARAMS_MAX_REUSE;
cleanup:
    if (kb)
	PORT_ZFree(kb, modLen);
    mp_clear(&k);
    mp_clear(&e);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

static SECStatus
init_blinding_params(struct RSABlindingParamsStr *rsabp, RSAPrivateKey *key,
                     mp_int *n, unsigned int modLen)
{
    SECStatus rv = SECSuccess;
    mp_err err = MP_OKAY;
    MP_DIGITS(&rsabp->f) = 0;
    MP_DIGITS(&rsabp->g) = 0;
    /* initialize blinding parameters */
    CHECK_MPI_OK( mp_init(&rsabp->f) );
    CHECK_MPI_OK( mp_init(&rsabp->g) );
    /* List elements are keyed using the modulus */
    SECITEM_CopyItem(NULL, &rsabp->modulus, &key->modulus);
    CHECK_SEC_OK( generate_blinding_params(rsabp, key, n, modLen) );
    return SECSuccess;
cleanup:
    mp_clear(&rsabp->f);
    mp_clear(&rsabp->g);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

static SECStatus
get_blinding_params(RSAPrivateKey *key, mp_int *n, unsigned int modLen,
                    mp_int *f, mp_int *g)
{
    SECStatus rv = SECSuccess;
    mp_err err = MP_OKAY;
    int cmp;
    PRCList *el;
    struct RSABlindingParamsStr *rsabp = NULL;
    /* Init the list if neccessary (the init function is only called once!) */
    if (blindingParamsList.lock == NULL) {
	if (PR_CallOnce(&coBPInit, init_blinding_params_list) != PR_SUCCESS) {
	    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
	    return SECFailure;
	}
    }
    /* Acquire the list lock */
    PZ_Lock(blindingParamsList.lock);
    /* Walk the list looking for the private key */
    for (el = PR_NEXT_LINK(&blindingParamsList.head);
         el != &blindingParamsList.head;
         el = PR_NEXT_LINK(el)) {
	rsabp = (struct RSABlindingParamsStr *)el;
	cmp = SECITEM_CompareItem(&rsabp->modulus, &key->modulus);
	if (cmp == 0) {
	    /* Check the usage counter for the parameters */
	    if (--rsabp->counter <= 0) {
		/* Regenerate the blinding parameters */
		CHECK_SEC_OK( generate_blinding_params(rsabp, key, n, modLen) );
	    }
	    /* Return the parameters */
	    CHECK_MPI_OK( mp_copy(&rsabp->f, f) );
	    CHECK_MPI_OK( mp_copy(&rsabp->g, g) );
	    /* Now that the params are located, release the list lock. */
	    PZ_Unlock(blindingParamsList.lock); /* XXX when fails? */
	    return SECSuccess;
	} else if (cmp > 0) {
	    /* The key is not in the list.  Break to param creation. */
	    break;
	}
    }
    /* At this point, the key is not in the list.  el should point to the
    ** list element that this key should be inserted before.  NOTE: the list
    ** lock is still held, so there cannot be a race condition here.
    */
    rsabp = (struct RSABlindingParamsStr *)
              PORT_ZAlloc(sizeof(struct RSABlindingParamsStr));
    if (!rsabp) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	goto cleanup;
    }
    /* Initialize the list pointer for the element */
    PR_INIT_CLIST(&rsabp->link);
    /* Initialize the blinding parameters 
    ** This ties up the list lock while doing some heavy, element-specific
    ** operations, but we don't want to insert the element until it is valid,
    ** which requires computing the blinding params.  If this proves costly,
    ** it could be done after the list lock is released, and then if it fails
    ** the lock would have to be reobtained and the invalid element removed.
    */
    rv = init_blinding_params(rsabp, key, n, modLen);
    if (rv != SECSuccess) {
	PORT_ZFree(rsabp, sizeof(struct RSABlindingParamsStr));
	goto cleanup;
    }
    /* Insert the new element into the list
    ** If inserting in the middle of the list, el points to the link
    ** to insert before.  Otherwise, the link needs to be appended to
    ** the end of the list, which is the same as inserting before the
    ** head (since el would have looped back to the head).
    */
    PR_INSERT_BEFORE(&rsabp->link, el);
    /* Return the parameters */
    CHECK_MPI_OK( mp_copy(&rsabp->f, f) );
    CHECK_MPI_OK( mp_copy(&rsabp->g, g) );
    /* Release the list lock */
    PZ_Unlock(blindingParamsList.lock); /* XXX when fails? */
    return SECSuccess;
cleanup:
    /* It is possible to reach this after the lock is already released.
    ** Ignore the error in that case.
    */
    PZ_Unlock(blindingParamsList.lock);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return SECFailure;
}

/*
** Perform a raw private-key operation 
**	Length of input and output buffers are equal to key's modulus len.
*/
SECStatus 
RSA_PrivateKeyOp(RSAPrivateKey *key, 
                 unsigned char *output, 
                 const unsigned char *input)
{
    unsigned int modLen;
    unsigned int offset;
    SECStatus rv;
    mp_err err;
    mp_int n, c, m;
    mp_int f, g;
    if (!key || !output || !input) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }
    MP_DIGITS(&n) = 0;
    MP_DIGITS(&c) = 0;
    MP_DIGITS(&m) = 0;
    MP_DIGITS(&f) = 0;
    MP_DIGITS(&g) = 0;
    CHECK_MPI_OK( mp_init(&n) );
    CHECK_MPI_OK( mp_init(&c) );
    CHECK_MPI_OK( mp_init(&m) );
    CHECK_MPI_OK( mp_init(&f) );
    CHECK_MPI_OK( mp_init(&g) );
    /* check input out of range (needs to be in range [0..n-1]) */
    modLen = rsa_modulusLen(&key->modulus);
    offset = (key->modulus.data[0] == 0) ? 1 : 0; /* may be leading 0 */
    if (memcmp(input, key->modulus.data + offset, modLen) >= 0) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }
    SECITEM_TO_MPINT(key->modulus, &n);
    OCTETS_TO_MPINT(input, &c, modLen);
    /* If blinding, compute pre-image of ciphertext by multiplying by
    ** blinding factor
    */
    if (nssRSAUseBlinding) {
	CHECK_SEC_OK( get_blinding_params(key, &n, modLen, &f, &g) );
	/* c' = c*f mod n */
	CHECK_MPI_OK( mp_mulmod(&c, &f, &n, &c) );
    }
    /* Do the private key operation m = c**d mod n */
    if ( key->prime1.len      == 0 ||
         key->prime2.len      == 0 ||
         key->exponent1.len   == 0 ||
         key->exponent2.len   == 0 ||
         key->coefficient.len == 0) {
	CHECK_SEC_OK( rsa_PrivateKeyOp(key, &m, &c, &n, modLen) );
    } else {
	CHECK_SEC_OK( rsa_PrivateKeyOpCRT(key, &m, &c, modLen) );
    }
    /* If blinding, compute post-image of plaintext by multiplying by
    ** blinding factor
    */
    if (nssRSAUseBlinding) {
	/* m = m'*g mod n */
	CHECK_MPI_OK( mp_mulmod(&m, &g, &n, &m) );
    }
    err = mp_to_fixlen_octets(&m, output, modLen);
    if (err >= 0) err = MP_OKAY;
cleanup:
    mp_clear(&n);
    mp_clear(&c);
    mp_clear(&m);
    mp_clear(&f);
    mp_clear(&g);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}
