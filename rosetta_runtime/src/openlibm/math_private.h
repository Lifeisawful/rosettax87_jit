/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * from: @(#)fdlibm.h 5.1 93/09/24
 * $FreeBSD: src/lib/msun/src/math_private.h,v 1.34 2011/10/21 06:27:56 das Exp $
 */

#ifndef _MATH_PRIVATE_H_
#define _MATH_PRIVATE_H_

#include <stdint.h>

/*
 * A union which permits us to convert between a double and two 32 bit
 * ints.
 */

typedef union {
    double value;
    struct {
        uint32_t lsw;
        uint32_t msw;
    } parts;
    struct {
        uint64_t w;
    } xparts;
} ieee_double_shape_type;

/* Get two 32 bit ints from a double.  */

#define EXTRACT_WORDS(ix0, ix1, d)   \
    do {                             \
        ieee_double_shape_type ew_u; \
        ew_u.value = (d);            \
        (ix0) = ew_u.parts.msw;      \
        (ix1) = ew_u.parts.lsw;      \
    } while (0)

/* Get the more significant 32 bit int from a double.  */

#define GET_HIGH_WORD(i, d)          \
    do {                             \
        ieee_double_shape_type gh_u; \
        gh_u.value = (d);            \
        (i) = gh_u.parts.msw;        \
    } while (0)

/* Get the less significant 32 bit int from a double.  */

#define GET_LOW_WORD(i, d)           \
    do {                             \
        ieee_double_shape_type gl_u; \
        gl_u.value = (d);            \
        (i) = gl_u.parts.lsw;        \
    } while (0)

/* Set a double from two 32 bit ints.  */

#define INSERT_WORDS(d, ix0, ix1)    \
    do {                             \
        ieee_double_shape_type iw_u; \
        iw_u.parts.msw = (ix0);      \
        iw_u.parts.lsw = (ix1);      \
        (d) = iw_u.value;            \
    } while (0)

/* Set the more significant 32 bits of a double from an int.  */

#define SET_HIGH_WORD(d, v)          \
    do {                             \
        ieee_double_shape_type sh_u; \
        sh_u.value = (d);            \
        sh_u.parts.msw = (v);        \
        (d) = sh_u.value;            \
    } while (0)

/* Set the less significant 32 bits of a double from an int.  */

#define SET_LOW_WORD(d, v)           \
    do {                             \
        ieee_double_shape_type sl_u; \
        sl_u.value = (d);            \
        sl_u.parts.lsw = (v);        \
        (d) = sl_u.value;            \
    } while (0)

#define STRICT_ASSIGN(type, lval, rval) ((lval) = (rval))

#endif /* !_MATH_PRIVATE_H_ */
