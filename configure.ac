#  ***************************************************************************
#  *                                                                         *
#  *                   _        _____               ____                     *
#  *           /\     | |      |  __ \      /\     |  _ \      /\            *
#  *          /  \    | |      | |  | |    /  \    | |_) |    /  \           *
#  *         / /\ \   | |      | |  | |   / /\ \   |  _ <    / /\ \          *
#  *        / ____ \  | |___   | |__| /  / ____ \  | |_) /  / ____ \         *
#  *       /_/    \_\ | ____|  |_____/  /_/    \_\ |____/  /_/    \_\        *
#  *                                                                         *
#  *    == {Port Knocking/Single Packet Authorization} Security Suite ==     *
#  *                                                                         *
#  ***************************************************************************
#  *                                                                         *
#  * This file is part of Aldaba Knocking Suite.                             *
#  *                                                                         *
#  * Copyright (c) 2010, Luis MartinGarcia. (aldabaknocking@gmail.com)       *
#  *                                                                         *
#  * Aldaba is free software; you can redistribute it and/or modify it under *
#  * the terms of the GNU General Public License as published by the Free    *
#  * Software Foundation; Version 2 of the License, with the exceptions,     *
#  * conditions and clarifications described in the file named LICENSE.txt,  *
#  * distributed with Aldaba or available from:                              *
#  * <http://www.aldabaknocking.com/LICENSE.txt>                             *
#  *                                                                         *
#  * Aldaba is distributed in the hope that it will be useful, but WITHOUT   *
#  * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or   *
#  * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License   *
#  * v2.0 for more details.                                                  *
#  *                                                                         *
#  * You should have received a copy of the GNU General Public License along *
#  * with Aldaba; if not, write to the Free Software Foundation, Inc.,       *
#  * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA                *
#  *                                                                         *
#  * Please check file LICENSE.txt for the complete version of the license,  *
#  * as this disclaimer does not contain the full information. Also, note    *
#  * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
#  * be possible to obtain copies of it under different, less restrictive,   *
#  * alternative licenses. Requests will be studied on a case by case basis. *
#  * If you wish to obtain Aldaba under a different license, please use the  *
#  * email address shown above.                                              *
#  *                                                                         *
#  ***************************************************************************/
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([ArgParserServer.cc])
AC_CONFIG_HEADER(aldaba_config.h)
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL

AC_MSG_CHECKING([if gcc is gcc4 or greater])
if test x"$GXX" = xno; then
  AC_MSG_RESULT([no])
else
  if test -z "$ac_cv_prog_CC" || test x"$CC" = xgcc4; then
    our_gcc="$CC"
  else
    our_gcc="$ac_cv_prog_CC"
  fi

  aldaba_gcc_major_version=0
  case `$our_gcc --version | sed -e 's,\..*,.,' -e q` in
    *4.)
      aldaba_gcc_major_version=4
      ;;
  esac

  if test 4 -ge $aldaba_gcc_major_version; then
    AC_MSG_RESULT([yes])
    CXXFLAGS="$CXXFLAGS -fno-strict-aliasing"
  else
    AC_MSG_RESULT([no])
  fi
fi



case "$host" in
  *alpha-dec-osf*)
    AC_DEFINE(DEC, [], "DEC Operating System")
    ;;
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD, [], "NetBSD Operating System")
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD, [], "OpenBSD Operating System")
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD, [], "FreeBSD Operating System")
    ;;
  *-sgi-irix5* | *-sgi-irix6*)
    AC_DEFINE(IRIX, [], "IRIX Operating System")
    ;;
  *mingw*) 
    AC_DEFINE(WIN32, [], "Microsoft Windows Operating System")
    ;;
  *cygwin*) 
    AC_DEFINE(WIN32, [], "Microsoft Windows Operating System")
    ;;  
  *-hpux*)
    AC_DEFINE(HPUX, [], "HPUX Operating System")
    ;;
  *-aix*)
    AC_DEFINE(AIX, [], "AIX Operating System")
    ;;
  *-solaris*)
    AC_DEFINE(SOLARIS, [], "Solaris Operating System")
    ;;
  *-sunos4*)
    AC_DEFINE(SUNOS, [], "SunOS Operating System")
    ;;
  *-linux*)
    AC_DEFINE(LINUX, [], "GNU/Linux Operating System")
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX, [], "Apple MacOS Operating System")
    ;;
esac

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live])
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h termio.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit gethostbyname gethostname gettimeofday inet_ntoa memmove memset pow socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strspn strstr strtol strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "Configuration process completed successfully."
