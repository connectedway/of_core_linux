/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */

#include <execinfo.h>
#include <stdlib.h>

#include "ofc/types.h"
#include "ofc/impl/backtraceimpl.h"

OFC_VOID ofc_backtrace_impl(OFC_VOID **trace, OFC_SIZET len)
{
  backtrace(trace, len);
}

OFC_VOID ofc_backtrace_sym_impl(OFC_CHAR ***trace, OFC_SIZET len)
{
  void *addr_trace[8];

  backtrace(addr_trace, len);
  *trace = backtrace_symbols(addr_trace, len);
}

OFC_VOID ofc_backtrace_sym_free_impl(OFC_CHAR **trace)
{
  free(trace);
}
