/*------------------------------------------------------------------
 * Encode/Decode Metadata Cross Protocol Encoding
 *
 * @file
 *
 * @author Amine Choukir <amchouki@cisco.com>
 * @author Yann Poupet <ypoupet@cisco.com>
 *
 *------------------------------------------------------------------
 */
#ifndef __MED_DBG_H__
#define __MED_DBG_H__

/* General debugging macro
 * Usually should be wrapped to give a consistent
 * look and feel of a module
 * */
#ifdef MED_DEBUG
#include <stdio.h>
#define DEBUG(str,...) fprintf(stderr, str, ##__VA_ARGS__)
#else
#define DEBUG(str,...)
#endif

#define DEBUG_ERR(str,...) DEBUG("\nMED ERR [%s:%d]" str, __FUNCTION__,\
__LINE__, ##__VA_ARGS__)

#define DEBUG_INVALID DEBUG("\nMED INVALID [%s:%d]", __FUNCTION__,\
__LINE__)

#endif /* __MED_DBG_H__ */

