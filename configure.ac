AC_INIT(kens, 0.5, godslord@sparcs.kaist.ac.kr)
AC_PREFIX_DEFAULT(`pwd`)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(kens, 0.5)
AM_CONFIG_HEADER(src/config.h:src/config.h.in)

# options
AC_ARG_ENABLE(efence,[    --enable-efence    use electric fence to debug],[],enable_efence="no")
AC_ARG_WITH(dmalloc, [    --with-dmalloc     use dmalloc to debug memory],[],with_dmalloc="no")

#programs
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_LN_S

#libraries
AC_CHECK_FUNC(socket, :, [
	AC_CHECK_LIB(socket, main)
	AC_CHECK_LIB(net, main)
	AC_CHECK_LIB(nsl_s, main)
	AC_CHECK_LIB(nsl, main)
	AC_CHECK_LIB(inet, socket)
	AC_CHECK_LIB(gen, main)
])
AC_CHECK_FUNCS(inet_aton)
AC_CHECK_FUNCS(poll)
AC_CHECK_LIB(xml2, xmlBufferCreate)
AC_CHECK_LIB(pthread, pthread_create)

if test $with_dmalloc != no ; then
	if test $with_dmalloc != yes ; then
		CPPFLAGS="$CPPFLAGS -I$with_dmalloc/include"
		LDFLAGS="$LDFLAGS -L$with_dmalloc/lib"
	fi
	AC_CHECK_HEADERS(dmalloc.h)
	AC_CHECK_LIB(dmalloc, dmalloc_shutdown)
#	if test $ac_cv_header_dmalloc_h = yes -a \
#		$ac_cv_lib_dmalloc_dmalloc_shutdown = yes ; then
#		CFLAGS="$CFLAGS -Ddmalloc"
#	fi
fi

if test $enable_efence = yes ; then
AC_CHECK_LIB(efence, memalign)
fi

#headers

# typedefs and structures
AC_TYPE_PID_T

CFLAGS="-g"

#functions
case "$target" in
	*linux*)
		CFLAGS="$CFLAGS -D_BSD_SOURCE"
		;;
	*)
		;;
esac

#output

CONFIGURE_DATE=`date`
AC_SUBST(CONFIGURE_DATE)

AC_CONFIG_FILES(
	Makefile
	src/Makefile
	test/Makefile
)
AC_OUTPUT

