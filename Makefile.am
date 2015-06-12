lib_LTLIBRARIES = libufpidentity.la
libufpidentity_la_SOURCES = identity.c identity-openssl-bridge.c identity-resolver.c identity-xml-parser.c picohttpparser.c strmap.c
libufpidentity_la_LDFLAGS = -version-info 1:0:0
ACLOCAL_AMFLAGS=-I m4
libufpidentity_la_CFLAGS = ${LIBXML_INCLUDES} -I ${OPENSSL_INCLUDES}
super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile
