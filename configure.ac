#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT(TUPm,2.4-Harlock,uptimeprj_support@nextworlds.com)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/TUPm.c])
AC_CONFIG_HEADERS([config.h])

AC_DEFUN([AC_MSG_TUP_END],[
	  echo "-------------------------------"
	  echo "Yeah baby... xD (Compile for ESX : ${enable_esx})"
	  echo "Use make && make install to deploy TUPm"
	  echo "This will install TUPm in ${prefix}"
	  echo "Don't forget to edit ${prefix}etc/TUPm.conf"
	  echo "Enjoy...Tugs"
	  echo "--------------------------------"
	  ])

AC_DEFUN([AC_PRINT_ARGS],[
	  echo TUPm Application directory : ${prefix}
	  echo TUPm Binary directory      : ${bindir}
	  echo TUPm Man directory         : ${mandir}
	  ])

AC_ARG_ENABLE([esx],
              [AC_HELP_STRING([--enable-esx=@<:@yes/no@:>@],
                              [Compile for ESX/ESXi platform @<:@default=no@:>@])],
              [],
              [enable_esx=no])

AC_DEFUN([AC_CFLAG_SET], [
	    ac_uname_str=`uname`
	    test "$ac_uname_str" = "SunOS" && CFLAGS="$CFLAGS -lnsl -lsocket"
	    test "x$enable_esx" = "xyes" && CFLAGS="$CFLAGS -DGOESX"
	    ]) 

# Enable expanding of shebang: get a usable BIN_PATH. Should include
# auto-archive snippet here, instead of quoting it.
AC_DEFUN([AC_DEFINE_DIR], [
	    test "$prefix" = "NONE" && prefix="$HOME/TUPm/"
	    ac_define_dir=`eval echo [$]$2`
	    ac_define_dir=`eval echo [$]ac_define_dir`
	    $1="$ac_define_dir"
	    AC_SUBST($1)
	    bindir="$ac_define_dir"
	    AC_SUBST(bindir)
	    ])

AC_DEFINE_DIR([prefix],[prefix])

AC_PRINT_ARGS
# Checks for programs.
AC_PROG_CC
AC_CFLAG_SET
# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h assert.h strings.h sys/ioctl.h sys/socket.h syslog.h unistd.h utmpx.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm getcwd gethostbyname select socket strerror strrchr strstr sysinfo uname])

AC_CONFIG_FILES([Makefile
                 skel/Makefile
                 src/Makefile])
AC_OUTPUT
AC_MSG_TUP_END
