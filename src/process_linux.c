/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#define _GNU_SOURCE
#include <link.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/process.h"
#include "ofc/libc.h"
#include "ofc/thread.h"

#include "ofc/impl/consoleimpl.h"

#include "ofc/heap.h"

extern char **environ ;

OFC_PROCESS_ID ofc_process_get_impl(OFC_VOID) {
  pid_t pid ;

  pid = getpid() ;
  return ((OFC_PROCESS_ID) pid) ;
}

OFC_VOID ofc_process_block_signal(OFC_INT signal) {
  sigset_t new_set ;
  sigset_t old_set ;

  sigemptyset (&new_set) ;
  sigaddset (&new_set, signal) ;

  pthread_sigmask (SIG_BLOCK, &new_set, &old_set) ;

}

OFC_VOID ofc_process_unblock_signal(OFC_INT signal) {
  sigset_t new_set ;

  sigemptyset (&new_set) ;
  sigaddset (&new_set, signal) ;

  pthread_sigmask (SIG_UNBLOCK, &new_set, OFC_NULL) ;
}

OFC_VOID ofc_process_signal (OFC_PROCESS_ID process, OFC_INT signal,
			     OFC_INT value) {
  union sigval si_val ;

  si_val.sival_int = value ;
  sigqueue (process, signal, si_val) ;
}

OFC_BOOL ofc_process_term_trap_impl (OFC_PROCESS_TRAP_HANDLER trap) {
  struct sigaction action ;
  OFC_BOOL ret ;

  ret = OFC_FALSE ;
  sigemptyset (&action.sa_mask) ;
  action.sa_handler = trap ;
  action.sa_flags = 0 ;

  if (sigaction (SIGTERM, &action, OFC_NULL) == 0)
    ret = OFC_TRUE ;

  return (ret) ;
}

OFC_HANDLE ofc_process_exec_impl (OFC_CTCHAR *name,
				 OFC_TCHAR *uname,
				 OFC_INT argc,
				  OFC_CHAR **argv)  {
  OFC_HANDLE hProcess ;
  OFC_CHAR *cname ;
  OFC_CHAR **exec_argv ;
  OFC_INT i ;
  pid_t pid ;
  int ret ;
  OFC_CHAR *cuname ;
  struct passwd *user ;

  /*
   * When the compiler is optimized, it can be tricked with the conditionals
   * used in forks and vforks.  This will cause it not to take the correct
   * value for pid2.  Therefore, set this to volatile.
   */
  volatile pid_t pid2 ;

  cname = ofc_tstr2cstr (name) ;
  cuname = ofc_tstr2cstr (uname) ;
  exec_argv = ofc_malloc (sizeof (OFC_CHAR *) * (argc+1)) ;
  for (i = 0 ; i < argc ; i++)
    exec_argv[i] = argv[i] ;
  exec_argv[i] = OFC_NULL ;

  hProcess = OFC_INVALID_HANDLE_VALUE ;

  pid2 = 0 ;
  pid = vfork() ;
  if (pid < 0)
    {
      ofc_process_crash ("Unable to Fork First Process\n") ;
    }
  else if (pid == 0)
    {
      int ret2 ;
      int pidt ;

      /* We are the first Child */
      ret2 = 1 ;
      pidt = fork() ;

      if (pidt < 0)
	{
	  ofc_process_crash("Unable to Fork Second Process\n") ;
	}
      else if (pidt == 0)
	{
	  int ret3 ;

	  if (cuname != OFC_NULL)
	    {
	      user = getpwnam(cuname) ;
	      if (user != OFC_NULL)
		{
		  (void)!setgid (user->pw_gid) ;
		  (void)!setuid (user->pw_uid) ;
		}
	    }
	  ret3 = execve (cname, exec_argv, environ) ;
	  if (ret3 < 0)
	    ofc_process_crash("Unable to Exec the Daemon\n") ;
	  /*
	   * Although we exit with a return code, we are detached, so 
	   * no one is looking for it
	   */
	  _exit(1) ;
	}
      else
	{
	  ret2 = 0 ;
	}
      /*
       * This will be returned to the parent in his waitpid
       */
      pid2 = pidt ;
      _exit(ret2) ;
    }
  else
    {
      /* 
       * We are the original process, The first child will exit 
       * immediately after spawning the daemon
       */
      waitpid (pid, &ret, 0) ;
      if (ret == 0)
	{
	  OFC_DWORD_PTR pid2l = (OFC_DWORD_PTR) pid2 ;
	  hProcess = 
	    ofc_handle_create (OFC_HANDLE_PROCESS, (OFC_VOID *) pid2l) ;
	}
    }

  ofc_free(cuname) ;
  ofc_free(cname) ;
  ofc_free(exec_argv) ;

  return (hProcess) ;
}

OFC_PROCESS_ID ofc_process_get_id_impl (OFC_HANDLE hProcess)
{
  pid_t pid ;
  OFC_DWORD_PTR pidl ;

  pidl = (OFC_DWORD_PTR) ofc_handle_lock (hProcess) ;
  pid = (pid_t) pidl ;

  if (pid != (pid_t) 0)
    ofc_handle_unlock (hProcess) ;

  return ((OFC_PROCESS_ID) pid) ;
}
  
OFC_VOID ofc_process_term_impl(OFC_HANDLE hProcess) 
{
  pid_t pid ;
  OFC_DWORD_PTR pidl ;

  pidl = (OFC_DWORD_PTR) ofc_handle_lock(hProcess) ;
  pid = (pid_t) pidl ;

  kill (pid, SIGTERM) ;

  ofc_handle_destroy(hProcess) ;
  ofc_handle_unlock(hProcess) ;
}

OFC_VOID ofc_process_kill_impl(OFC_PROCESS_ID pid) {
  kill (pid, SIGTERM) ;
}

OFC_VOID
ofc_process_crash_impl(OFC_CCHAR *obuf) {
  ofc_write_console_impl(obuf) ;
  _Exit(EXIT_SUCCESS);
}  

#define OBUF_SIZE 200
static uint64_t core_load_addr = 0;
static uint64_t smb_load_addr = 0;

static int process_dump_libs_callback(struct dl_phdr_info *info,
				      size_t size,
				      void *data)
{
  const char *name;
  name = info->dlpi_name;
  OFC_CHAR obuf[OBUF_SIZE];
  
  if (ofc_substr("libof_core_jni", name) >= 0)
    {
      core_load_addr = info->dlpi_addr;
      ofc_snprintf(obuf, OBUF_SIZE,
		   "Library Load: %s: 0x%016x\n", "libof_core_jni",
		   (uint64_t) core_load_addr);
      ofc_write_console_impl(obuf);
    }
  else if (ofc_substr("libof_smb_jni", name) >= 0)
    {
      smb_load_addr = info->dlpi_addr;
      ofc_snprintf(obuf, OBUF_SIZE,
		   "Library Load: %s: 0x%016x\n", "libof_smb_jni",
		   (uint64_t) smb_load_addr);
      ofc_write_console_impl(obuf);
    }

  return (0);
}

OFC_VOID
ofc_process_dump_libs_impl(OFC_VOID)
{
  dl_iterate_phdr(process_dump_libs_callback, OFC_NULL);
}

OFC_VOID *ofc_process_relative_addr_impl(OFC_VOID *addr)
{
  OFC_ULONG_PTR ptr;

  ptr = (OFC_ULONG_PTR) addr;
  if (core_load_addr == 0 || smb_load_addr == 0)
    ptr = 0;
  else if (core_load_addr > smb_load_addr)
    {
      if (ptr > core_load_addr)
	{
	  ptr -= core_load_addr;
	}
      else if (ptr > smb_load_addr)
	{
	  ptr -= smb_load_addr;
	  /*
	   * set the top bit so we know it's in smb lib
	   */
	  ptr |= 0x8000000000000000LL;
	}
      else
	ptr = 0;
    }
  else if (smb_load_addr > core_load_addr)
    {
      if (ptr > smb_load_addr)
	{
	  ptr -= smb_load_addr;
	  /*
	   * set the top bit so we know it's in smb lib
	   */
	  ptr |= 0x8000000000000000LL;
	}
      else if (ptr > core_load_addr)
	{
	  ptr -= core_load_addr;
	}
      else
	ptr = 0;
    }
  else
    ptr = 0;
  return ((OFC_VOID *) ptr);
}
