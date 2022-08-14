/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#include <pthread.h>
#include <signal.h>
#define __USE_XOPEN
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#include "ofc/core.h"
#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/thread.h"
#include "ofc/sched.h"
#include "ofc/impl/threadimpl.h"
#include "ofc/libc.h"
#include "ofc/waitset.h"
#include "ofc/event.h"
#include "ofc/heap.h"

/** \{ */

typedef struct
{
  pthread_t thread ;
  OFC_DWORD (*scheduler)(OFC_HANDLE hThread, OFC_VOID *context)  ;
  OFC_VOID *context ;
  OFC_DWORD ret ;
  OFC_BOOL deleteMe ;
  OFC_HANDLE handle ;
  OFC_THREAD_DETACHSTATE detachstate ;
  OFC_HANDLE wait_set ;
  OFC_HANDLE hNotify ;
} LINUX_THREAD ;

static void *ofc_thread_launch(void *arg)
{
  LINUX_THREAD *linuxThread ;

  linuxThread = arg ;

  linuxThread->ret = (linuxThread->scheduler)(linuxThread->handle,
						linuxThread->context) ;

  if (linuxThread->hNotify != OFC_HANDLE_NULL)
    ofc_event_set(linuxThread->hNotify) ;

  if (linuxThread->detachstate == OFC_THREAD_DETACH)
    {
      pthread_cancel (linuxThread->thread) ;
      ofc_handle_destroy(linuxThread->handle) ;
      ofc_free(linuxThread) ;
    }
  return (OFC_NULL) ;
}

OFC_HANDLE ofc_thread_create_impl(OFC_DWORD(scheduler)(OFC_HANDLE hThread,
                                                       OFC_VOID *context),
                                  OFC_CCHAR *thread_name,
                                  OFC_INT thread_instance,
                                  OFC_VOID *context,
                                  OFC_THREAD_DETACHSTATE detachstate,
                                  OFC_HANDLE hNotify)
{
  LINUX_THREAD *linuxThread ;
  OFC_HANDLE ret ;
  pthread_attr_t attr ;

  ret = OFC_HANDLE_NULL ;
  linuxThread = ofc_malloc(sizeof (LINUX_THREAD)) ;
  if (linuxThread != OFC_NULL)
    {
      linuxThread->wait_set = OFC_HANDLE_NULL ;
      linuxThread->deleteMe = OFC_FALSE ;
      linuxThread->scheduler = scheduler ;
      linuxThread->context = context ;
      linuxThread->hNotify = hNotify ;
      linuxThread->handle =
	ofc_handle_create (OFC_HANDLE_THREAD, linuxThread) ;
      linuxThread->detachstate = detachstate ;
      pthread_attr_init (&attr) ;

      if (linuxThread->detachstate == OFC_THREAD_DETACH)
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) ;
      else if (linuxThread->detachstate == OFC_THREAD_JOIN)
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) ;

      if (pthread_create (&linuxThread->thread, &attr,
			  ofc_thread_launch, linuxThread) != 0)
	{
	  ofc_handle_destroy(linuxThread->handle) ;
	  ofc_free(linuxThread) ;
	}
      else
	ret = linuxThread->handle ;
    }
  return (ret) ;
}

OFC_VOID
ofc_thread_set_waitset_impl(OFC_HANDLE hThread, OFC_HANDLE wait_set)
{
  LINUX_THREAD *linuxThread ;

  linuxThread = ofc_handle_lock(hThread) ;
  if (linuxThread != OFC_NULL)
    {
      linuxThread->wait_set = wait_set ;
      ofc_handle_unlock(hThread) ;
    }
}

OFC_VOID ofc_thread_delete_impl(OFC_HANDLE hThread)
{
  LINUX_THREAD *linuxThread ;

  linuxThread = ofc_handle_lock(hThread) ;
  if (linuxThread != OFC_NULL)
    {
      linuxThread->deleteMe = OFC_TRUE ;
      if (linuxThread->wait_set != OFC_HANDLE_NULL)
	ofc_waitset_wake(linuxThread->wait_set) ;
      ofc_handle_unlock(hThread) ;
    }
}

OFC_VOID ofc_thread_wait_impl(OFC_HANDLE hThread)
{
  LINUX_THREAD *linuxThread ;
  int ret ;

  linuxThread = ofc_handle_lock(hThread) ;
  if (linuxThread != OFC_NULL)
    {
      if (linuxThread->detachstate == OFC_THREAD_JOIN)
	{
	  ret = pthread_join (linuxThread->thread, OFC_NULL) ;
	  ofc_handle_destroy(linuxThread->handle) ;
	  ofc_free(linuxThread) ;
	}
      ofc_handle_unlock(hThread) ;
    }
}

OFC_BOOL ofc_thread_is_deleting_impl(OFC_HANDLE hThread)
{
  LINUX_THREAD *linuxThread ;
  OFC_BOOL ret ;

  ret = OFC_FALSE ;
  linuxThread = ofc_handle_lock (hThread) ;
  if (linuxThread != OFC_NULL)
    {
      if (linuxThread->deleteMe)
	ret = OFC_TRUE ;
      ofc_handle_unlock(hThread) ;
    }
  return (ret) ;
}

OFC_VOID ofc_sleep_impl(OFC_DWORD milliseconds)
{
  useconds_t useconds ;

  if (milliseconds == OFC_INFINITE)
    {
      for (;1;)
	/* Sleep for a day, then more */
	sleep (60*60*24) ;
    }
  else
    {
      useconds = milliseconds * 1000 ;
      usleep (useconds) ;
    }
  pthread_testcancel() ;
}

OFC_DWORD ofc_thread_create_variable_impl(OFC_VOID)
{
  pthread_key_t key ;

  pthread_key_create (&key, NULL) ;
  return ((OFC_DWORD) key) ;
}

OFC_VOID ofc_thread_destroy_variable_impl(OFC_DWORD dkey)
{
  pthread_key_t key ;
  key = (pthread_key_t) dkey ;

  pthread_key_delete (key);
}

OFC_DWORD_PTR ofc_thread_get_variable_impl(OFC_DWORD var)
{
  return ((OFC_DWORD_PTR) pthread_getspecific ((pthread_key_t) var)) ;
}

OFC_VOID ofc_thread_set_variable_impl(OFC_DWORD var, OFC_DWORD_PTR val)
{
  pthread_setspecific ((pthread_key_t) var, (OFC_LPVOID) val) ;
}

/*
 * These routines are noops on platforms that support TLS
 */
OFC_CORE_LIB OFC_VOID
ofc_thread_create_local_storage_impl(OFC_VOID)
{
}

OFC_CORE_LIB OFC_VOID
ofc_thread_destroy_local_storage_impl(OFC_VOID)
{
}

OFC_CORE_LIB OFC_VOID
ofc_thread_init_impl(OFC_VOID)
{
}

OFC_CORE_LIB OFC_VOID
ofc_thread_destroy_impl(OFC_VOID)
{
}

OFC_CORE_LIB OFC_VOID
ofc_thread_detach_impl(OFC_HANDLE hThread)
{
  LINUX_THREAD *linuxThread ;

  linuxThread = ofc_handle_lock (hThread) ;
  if (linuxThread != OFC_NULL)
    {
      linuxThread->detachstate = OFC_THREAD_DETACH;
      pthread_detach(linuxThread->thread);
      ofc_handle_unlock(hThread) ;
    }
}
/** \} */
