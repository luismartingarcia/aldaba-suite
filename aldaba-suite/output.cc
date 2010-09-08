
/***************************************************************************
 *                                                                         *
 *                   _        _____               ____                     *
 *           /\     | |      |  __ \      /\     |  _ \      /\            *
 *          /  \    | |      | |  | |    /  \    | |_) |    /  \           *
 *         / /\ \   | |      | |  | |   / /\ \   |  _ <    / /\ \          *
 *        / ____ \  | |___   | |__| /  / ____ \  | |_) /  / ____ \         *
 *       /_/    \_\ | ____|  |_____/  /_/    \_\ |____/  /_/    \_\        *
 *                                                                         *
 *    == {Port Knocking/Single Packet Authorization} Security Suite ==     *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 * This file is part of Aldaba Knocking Suite.                             *
 *                                                                         *
 * Copyright (c) 2010, Luis MartinGarcia. (aldabaknocking@gmail.com)       *
 *                                                                         *
 * Aldaba is free software; you can redistribute it and/or modify it under *
 * the terms of the GNU General Public License as published by the Free    *
 * Software Foundation; Version 2 of the License, with the exceptions,     *
 * conditions and clarifications described in the file named LICENSE.txt,  *
 * distributed with Aldaba or available from:                              *
 * <http://www.aldabaknocking.com/LICENSE.txt>                             *
 *                                                                         *
 * Aldaba is distributed in the hope that it will be useful, but WITHOUT   *
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or   *
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License   *
 * v2.0 for more details.                                                  *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with Aldaba; if not, write to the Free Software Foundation, Inc.,       *
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA                *
 *                                                                         *
 * Please check file LICENSE.txt for the complete version of the license,  *
 * as this disclaimer does not contain the full information. Also, note    *
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/
#include "aldaba.h"
#include "output.h"
#include "ClientOps.h"

extern ClientOps o;


/** Print fatal error messages to stderr or syslog and then exit() */
void fatal(int type, const char *str, ...) {

 va_list  list;
 char errstr[MAX_OUTPUT_MSG_LEN];
 memset(errstr,0, MAX_OUTPUT_MSG_LEN);

  va_start(list, str);

  fflush(stdout);

  if (type == OUT_0 || type == LOG_0 || type == PERR_0) { /* Do nothing*/
    #ifndef DO_NOT_EXIT_ON_FATAL_ERRORS
        exit(EXIT_FAILURE);
    #endif
  }
  else if (type >= OUT_1 && type <= OUT_9){ /* Print to stdout */
      if (type <= o.getVerbosityLevel() ){
        vfprintf(stderr, str, list);
        fprintf(stderr,"\n");
      }
  }
  else if (type >= LOG_1 && type <= LOG_9){ /* Log to syslog */
      if( type <= o.getLoggingLevel()+10 ){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list);
        syslog(LOG_ERR, errstr, "");
      }
  }
  else if (type >= PERR_1 && type <= PERR_9){ /* Call perror() */
      if (type <= (o.getVerbosityLevel()+20)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        perror(errstr);
      }
  }
  else if (type == ALL){ /* Call perror and log to syslog */
      if(o.getVerbosityLevel()>0 && o.getLoggingLevel()>0){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_WARNING, errstr, "");
        perror(errstr);

      }
  }
  else{
      if(o.getLoggingLevel()>=1)
        syslog(LOG_WARNING, "Wrong type value in fatal() function");
  }
  va_end(list);

/* This is provided just in case someone wants to continue execution
   after a fatal error. However, as fatal() is normally called when
   NULL pointers are detected or invalid values are passed to a function,
   preventing exit() will probably cause the application to segfault or
   behave in an unpredictable way.
*/
#ifndef DO_NOT_EXIT_ON_FATAL_ERRORS
  exit(EXIT_FAILURE);
#endif

} /* End of fatal() */


/** Print warnings to stderr or syslog */
int warning(int type, const char *str, ...){

 va_list  list;
 char errstr[MAX_OUTPUT_MSG_LEN];
 memset(errstr,0, MAX_OUTPUT_MSG_LEN);

  va_start(list, str);

  fflush(stdout);

  if (type == OUT_0 || type == LOG_0 || type == PERR_0) { /* Do nothing*/
    return -2;
  }
  else if (type >= OUT_1 && type <= OUT_9){ /* Print to stdout */
      if (type <= o.getVerbosityLevel()){
        vfprintf(stderr, str, list);
      }
  }
  else if (type >= LOG_1 && type <= LOG_9){ /* Log to syslog */
      if( type <= (o.getLoggingLevel()+10)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_ERR, errstr, "");
      }
  }
  else if (type >= PERR_1 && type <= PERR_9){ /* Call perror() */
      if (type <= (o.getVerbosityLevel()+20)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        perror(errstr);
      }
  }
  else if (type == ALL){ /* Call perror and log to syslog */
      if(o.getVerbosityLevel()>0 && o.getLoggingLevel()>0){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_WARNING, errstr, "");
        perror(errstr);

      }
  }
  else{
      if(o.getLoggingLevel()>=1)
        syslog(LOG_WARNING, "Wrong type value in warning() function");
  }

  va_end(list);

  return -1;

} /* End of warning() */


/** Print regular messages to stdout or to syslog */
int output(int type, const char *str, ...){
 va_list  list;
 char errstr[MAX_OUTPUT_MSG_LEN];
 memset(errstr,0, MAX_OUTPUT_MSG_LEN);

  va_start(list, str);
  fflush(stdout);

  if (type == OUT_0 || type == LOG_0 || type == PERR_0) { /* Do nothing*/
    return -2;
  }
  else if (type >= OUT_1 && type <= OUT_9){ /* Print to stdout */
      if (type <= o.getVerbosityLevel())
        vfprintf(stdout, str, list);
  }
  else if (type >= LOG_1 && type <= LOG_9){ /* Log to syslog */
      if( type <= (o.getLoggingLevel()+10)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_ERR, errstr, "");
      }
  }
  else if (type >= PERR_1 && type <= PERR_9){ /* Call perror() */
      if (type <= (o.getVerbosityLevel()+20)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        perror(errstr);
      }
  }
  else if (type == ALL){ /* Call perror and log to syslog */
      if(o.getVerbosityLevel()>0 && o.getLoggingLevel()>0){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_WARNING, errstr, "");
        perror(errstr);
      }
  }
  else{
      if(o.getLoggingLevel()>=1)
        syslog(LOG_WARNING, "Wrong type value in output() function (%d)", type);
  }
  va_end(list);
  return -1;
} /* End of output() */



static const char *get_indent_trailing(int level){
  static char buffer[128];

  if(level<=0){
      buffer[0]='\0';
  }else if(level==1){
    snprintf(buffer, sizeof(buffer)-1, " ");
  }else{
    snprintf(buffer, sizeof(buffer)-1, " ");
    for(int i=1; i<level; i++)
        strncat(buffer, "|  ", sizeof(buffer)-1);
  }
  return buffer;
} /* End of get_indent_trailing() */


/** Print regular messages to stdout or to syslog */
int indent(int type, unsigned indents, const char *str, ...){
  va_list  list;
  char errstr[MAX_OUTPUT_MSG_LEN];
  memset(errstr,0, MAX_OUTPUT_MSG_LEN);

  va_start(list, str);
  fflush(stdout);

  if (type == OUT_0 || type == LOG_0 || type == PERR_0) { /* Do nothing*/
    return -2;
  }
  else if (type >= OUT_1 && type <= OUT_9){ /* Print to stdout */
      if (type <= o.getVerbosityLevel()){
          printf("%s|_",  get_indent_trailing(indents));
          vfprintf(stdout, str, list);
      }
  }
  else if (type >= LOG_1 && type <= LOG_9){ /* Log to syslog */
      if( type <= (o.getLoggingLevel()+10)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_ERR, errstr, "");
      }
  }
  else if (type >= PERR_1 && type <= PERR_9){ /* Call perror() */
      if (type <= (o.getVerbosityLevel()+20)){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        perror(errstr);
      }
  }
  else if (type == ALL){ /* Call perror and log to syslog */
      if(o.getVerbosityLevel()>0 && o.getLoggingLevel()>0){
        vsnprintf(errstr, MAX_OUTPUT_MSG_LEN-1, str, list),
        syslog(LOG_WARNING, errstr, "");
        perror(errstr);
      }
  }
  else{
      if(o.getLoggingLevel()>=1)
        syslog(LOG_WARNING, "Wrong type value in output() function (%d)", type);
  }
  va_end(list);
  return -1;
} /* End of output() */



