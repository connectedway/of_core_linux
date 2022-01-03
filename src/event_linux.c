/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/event.h"

#include "ofc/heap.h"
#include "ofc/impl/eventimpl.h"
#include "ofc/impl/waitsetimpl.h"

typedef struct
{
  OFC_EVENT_TYPE eventType ;
  OFC_BOOL signalled ;
  pthread_cond_t pthread_cond ;
  pthread_mutex_t pthread_mutex ;
  pthread_mutexattr_t pthread_mutexattr ;
} LINUX_EVENT ;

OFC_HANDLE ofc_event_create_impl(OFC_EVENT_TYPE eventType) {
  LINUX_EVENT *linux_event ;
  OFC_HANDLE hLinuxEvent ;
  pthread_cond_t pthread_cond_initializer = PTHREAD_COND_INITIALIZER ;
  pthread_mutex_t pthread_mutex_initializer = PTHREAD_MUTEX_INITIALIZER ;

  hLinuxEvent = OFC_HANDLE_NULL ;
  linux_event = ofc_malloc(sizeof (LINUX_EVENT)) ;
  if (linux_event != OFC_NULL)
    {
      linux_event->eventType = eventType ;
      linux_event->signalled = OFC_FALSE ;
      linux_event->pthread_cond = pthread_cond_initializer ;
      linux_event->pthread_mutex = pthread_mutex_initializer ;
      pthread_mutexattr_init (&linux_event->pthread_mutexattr) ;
      pthread_mutexattr_settype (&linux_event->pthread_mutexattr, 
				 PTHREAD_MUTEX_ERRORCHECK) ;
      pthread_cond_init (&linux_event->pthread_cond, NULL)  ;
      pthread_mutex_init (&linux_event->pthread_mutex, 
			  &linux_event->pthread_mutexattr) ;
      hLinuxEvent = ofc_handle_create (OFC_HANDLE_EVENT, linux_event) ;
    }
  return (hLinuxEvent) ;
}

OFC_VOID ofc_event_set_impl(OFC_HANDLE hEvent) {
  LINUX_EVENT *linuxEvent ;
  OFC_HANDLE hWaitSet ;

  linuxEvent = ofc_handle_lock(hEvent) ;
  if (linuxEvent != OFC_NULL) {
      pthread_mutex_lock (&linuxEvent->pthread_mutex) ;

      linuxEvent->signalled = OFC_TRUE ;
      pthread_cond_broadcast (&linuxEvent->pthread_cond) ;
      
      hWaitSet = ofc_handle_get_wait_set (hEvent) ;
      if (hWaitSet != OFC_HANDLE_NULL) {
	  ofc_waitset_signal_impl (hWaitSet, hEvent) ;
	}
      pthread_mutex_unlock (&linuxEvent->pthread_mutex) ;

      ofc_handle_unlock(hEvent) ;
    }
}

OFC_VOID ofc_event_reset_impl(OFC_HANDLE hEvent) {
  LINUX_EVENT *linuxEvent ;

  linuxEvent = ofc_handle_lock(hEvent) ;
  if (linuxEvent != OFC_NULL) {
      pthread_mutex_lock (&linuxEvent->pthread_mutex) ;
      linuxEvent->signalled = OFC_FALSE ;
      pthread_mutex_unlock (&linuxEvent->pthread_mutex) ;
      ofc_handle_unlock(hEvent) ;
    }
}

OFC_EVENT_TYPE ofc_event_get_type_impl(OFC_HANDLE hEvent) {
{
  LINUX_EVENT *linux_event ;
  OFC_EVENT_TYPE eventType ;

  eventType = OFC_EVENT_AUTO ;
  linux_event = ofc_handle_lock(hEvent) ;
  if (linux_event != OFC_NULL) {
      eventType = linux_event->eventType ;
      ofc_handle_unlock(hEvent) ;
    }
  return (eventType) ;
}

OFC_VOID ofc_event_destroy_impl(OFC_HANDLE hEvent) {
{
  LINUX_EVENT *linuxEvent ;

  linuxEvent = ofc_handle_lock(hEvent) ;
  if (linuxEvent != OFC_NULL)
    {
      pthread_cond_destroy (&linuxEvent->pthread_cond) ;
      pthread_mutex_destroy (&linuxEvent->pthread_mutex) ;
      pthread_mutexattr_destroy (&linuxEvent->pthread_mutexattr) ;
      ofc_free(linuxEvent) ;
      ofc_handle_destroy(hEvent) ;
      ofc_handle_unlock(hEvent) ;
    }
}

OFC_VOID ofc_event_wait_impl(OFC_HANDLE hEvent) {
{
  LINUX_EVENT *linux_event ;

  linux_event = ofc_handle_lock(hEvent) ;
  if (linux_event != OFC_NULL) {
      pthread_mutex_lock (&linux_event->pthread_mutex) ;
      if (!linux_event->signalled)
	pthread_cond_wait (&linux_event->pthread_cond,
			   &linux_event->pthread_mutex) ;
      if (linux_event->eventType == OFC_EVENT_AUTO)
	linux_event->signalled = OFC_FALSE ;

      pthread_mutex_unlock (&linux_event->pthread_mutex) ;
      ofc_handle_unlock(hEvent) ;
    }
}

OFC_BOOL ofc_event_test_impl(OFC_HANDLE hEvent) {
  LINUX_EVENT *linux_event ;
  BLUE_BOOL ret ;

  ret = OFC_TRUE ;
  linux_event = ofc_handle_lock(hEvent) ;
  if (linux_event != OFC_NULL) {
      pthread_mutex_lock (&linux_event->pthread_mutex) ;
      ret = linux_event->signalled ;
      pthread_mutex_unlock (&linux_event->pthread_mutex) ;
      ofc_handle_unlock(hEvent) ;
    }
  return (ret) ;
}

