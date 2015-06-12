AC_PREREQ(2.61)
AC_INIT(libufpidentity, 1.0, richardl@ufp.com)
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([identity.c], [identity-resolver.c], [identity-xml-parser.c], [identity-openssl-bridge.c], [picohttpparser.c],  [strmap.c])
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE 

AC_PROG_CC
AC_PROG_CC_STDC

AC_CHECK_HEADERS([sys/fsuid.h])
AC_CHECK_FUNCS([setfsuid])

PKG_PROG_PKG_CONFIG([0.25])
AC_SEARCH_LIBS([xmlReadDoc], [xml2], [libxml_includes=`$PKG_CONFIG --cflags libxml-2.0`])
AC_SEARCH_LIBS([SSL_library_init], [ssl])
AC_SEARCH_LIBS([BIO_new], [crypto])

AC_SUBST([LIBXML_INCLUDES], $libxml_includes)
AX_CHECK_OPENSSL
AX_CHECK_COMPILE_FLAG([-Wno-unused-result], [CFLAGS="$CFLAGS -Wno-unused-result"]) 
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
