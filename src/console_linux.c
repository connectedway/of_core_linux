/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "ofc/types.h"
#include "ofc/impl/consoleimpl.h"
#include "ofc/libc.h"

/**
 * \defgroup console_linux Linux Console Interface
 */

/** \{ */

/*
 * The Linux console handler supports syslog logging by default but
 * allows for a deployment to override that behavior and write to
 * a file within the file system.  This behavior is controlled by
 * the api ofc_framework_set_log_file or ofc_console_set_log_file.
 * The behavior is a round robin set of log files.  Each file will
 * be limited to a rollover size.  The size of the set is set 
 * with a max instance parameter.  And the log file name and location is
 * set with a pattern that should contain a single %d format character.
 * When stepping the file instance, the instance is incremented and a
 * new log file is generated using the pattern and the instance as the
 * file namee.
 */

/*
 * The default log file settings
 */
#define DEFAULT_ROLLOVER_SIZE 1048576
#define DEFAULT_MAX_INSTANCE 10

/*
 * Global variables used within this handler
 */
static int g_logfile_fd = -1 ;
static char *g_logfile_pattern = OFC_NULL;
static off_t g_rollover_size = DEFAULT_ROLLOVER_SIZE;
static int g_instance = 0;
static int g_max_instance = DEFAULT_MAX_INSTANCE;

static OFC_VOID close_log(OFC_VOID)
{
  if (g_logfile_fd != -1)
    close(g_logfile_fd);
  g_logfile_fd = -1;
}

static void open_log(void)
{
  char *logfile;
  int name_size;

  /*
   * Find the size of the resultant log file path (plus nil)
   */
  name_size = snprintf(logfile, 0, g_logfile_pattern, g_instance) + 1;
  /*
   * Allocate a buffer for it
   */
  logfile = malloc(name_size);
  /*
   * Now generate the logfile name
   */
  if (snprintf(logfile, name_size, g_logfile_pattern, g_instance) > name_size)
    {
      /*
       * Name exceeded buffer.  This is unexpected.  We'll use pattern as
       * file name.
       */
      free(logfile);
      logfile = strdup(g_logfile_pattern);
    }

  /*
   * Open file log file.  If the open fails, the g_logfile_id will be
   * -1.  No logging will occur.
   */
  g_logfile_fd = open (logfile,
		       O_CREAT | O_WRONLY | O_TRUNC,
		       S_IRWXU | S_IRWXG | S_IRWXO) ;
  /*
   * Get rid of temporary buffer
   */
  free(logfile);
}

static void free_log_file (void)
{
  /* 
   * close the log file.
   */
  close_log();
  /*
   * If a pattern is allocated, free it
   */
  if (g_logfile_pattern != NULL)
    {
      free(g_logfile_pattern);
      g_logfile_pattern = NULL;
    }
}

OFC_VOID
ofc_console_set_log_file_impl(OFC_CHAR *log_file,
			      OFC_LARGE_INTEGER rollover_size,
			      OFC_UINT max_instance)
{
  /*
   * clean up from any prior setting
   */
  free_log_file();

  /*
   * The default is syslog.  Check if we are logging to a file
   */
  if (log_file != NULL)
    {
      /*
       * Generate a new logfile pattern
       */
      g_logfile_pattern = strdup(log_file);
      /*
       * Reset the instance
       */
      g_instance = 0;
      /*
       * And open the log file
       */
      open_log();
  
      /*
       * Set the rollover size
       */
      if (rollover_size == 0)
	rollover_size = DEFAULT_ROLLOVER_SIZE;
      g_rollover_size = rollover_size;

      /*
       * Set the max instance
       */
      if (max_instance == 0)
	max_instance = DEFAULT_MAX_INSTANCE;
      g_max_instance = max_instance;
    }
}

OFC_VOID ofc_write_stdout_impl(OFC_CCHAR *obuf, OFC_SIZET len)
{
  (void)!write (STDOUT_FILENO, obuf, len) ;
  fsync (STDOUT_FILENO) ;
}

static OFC_VOID ofc_write_syslog(OFC_LOG_LEVEL level,
				 OFC_CCHAR *obuf, OFC_SIZET len)
{
  static int log_opened = 0;
  int priority;
  
  if (!log_opened)
    {
      log_opened = 1;
      openlog("openfiles", LOG_PID | LOG_CONS, LOG_USER);
    }

  switch (level)
    {
    case OFC_LOG_DEBUG:
      priority = LOG_DEBUG;
      break;
      
    case OFC_LOG_INFO:
      priority = LOG_INFO;
      break;
      
    case OFC_LOG_WARN:
      priority = LOG_WARNING;
      break;

    default:
    case OFC_LOG_FATAL:
      priority = LOG_ERR;
      break;
    }

  syslog (priority, "%.*s", (int) len, obuf);
}

/*
 * This routine is called by the upper layers to write to the 
 * system logs.  This will either wrrite to the syslog (if
 * g_logfile_pattern is NULL) or the overridden log file set
 * with the set_log_file api call
 */
OFC_VOID ofc_write_log_impl(OFC_LOG_LEVEL level,
			    OFC_CCHAR *obuf, OFC_SIZET len)
{
  /*
   * See if logfile pattern is null and we are writing to syslog
   * or if we were unable to open the log file
   */
  if (g_logfile_pattern == OFC_NULL || g_logfile_fd == -1)
    ofc_write_syslog(level, obuf, len);
  else
    {
      /*
       * We are writing to overridden log files
       */
      struct stat statbuf;
      /*
       * first check if we should step the log file
       * if stat fails, we simply won't step
       */
      if (fstat (g_logfile_fd, &statbuf) != -1)
	{
	  /*
	   * If we are larger than the rollover size, 
	   * close the log, increment the instance, roll over
	   * the instance if necessary, and reopen the log file
	   */
	  if (statbuf.st_size > g_rollover_size)
	    {
	      close_log();
	      g_instance++;
	      if (g_instance >= g_max_instance)
		g_instance = 0;
	      open_log();
	    }
	}
      time_t now;
      char timebuf[26];
      /*
       * Write a time stamp
       */
      now = time(NULL);
      ctime_r(&now, timebuf);
      /*
       * rid us of the newline
       */
      timebuf[24] = ' ';
      (void)!write (g_logfile_fd, timebuf, 25) ;
      /*
       * Now write the buffer
       */
      (void)!write (g_logfile_fd, obuf, len) ;
      fsync (g_logfile_fd) ;
    }
}

OFC_VOID ofc_write_console_impl(OFC_CCHAR *obuf)
{
  (void)!write (STDOUT_FILENO, obuf, ofc_strlen(obuf)) ;
  fsync (STDOUT_FILENO) ;
}

OFC_VOID ofc_read_stdin_impl(OFC_CHAR *inbuf, OFC_SIZET len)
{
  (void)!fgets (inbuf, len, stdin) ;
  if (ofc_strlen (inbuf) < len)
    len = ofc_strlen (inbuf) ;
  inbuf[len-1] = '\0' ;
}

OFC_VOID ofc_read_password_impl(OFC_CHAR *inbuf, OFC_SIZET len)
{
  char *pass ;

  pass = getpass ("") ;
  ofc_strncpy (inbuf, pass, len-1) ;
  inbuf[len] = '\0' ;
}

OFC_VOID ofc_console_init_impl(OFC_VOID)
{
  g_logfile_pattern = OFC_NULL;
  g_logfile_fd = -1;
}

OFC_VOID ofc_console_destroy_impl(OFC_VOID)
{
  free_log_file();
}

/** \} */
