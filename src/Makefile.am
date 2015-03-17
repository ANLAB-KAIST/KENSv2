bin_PROGRAMS = kens kensctrl ktcptest1 ktcptest2 ktcptest3 ktcptest4

lib_LIBRARIES = libiniparser.a libkens.a libktcp.a

DATASTRUCTURES_SRC=\
				   linked_list.c

KXML_SRC=\
		kxml.c

LOG_SRC=\
		 log.c remote_log.c

KMGMT_SRC=\
		  kmgmt.c

INIPARSER_SRC=\
			   iniparser.c dictionary.c strlib.c

KNET_COMMON_SRC=\
				 datalink.c mactable.c \
				 route.c krip.c \
				 ktcp.c \
				ktcp_easy_impl.c 

KNET_KERNEL_SRC=\
				  kernel_main.c \
				  kip.c \
				  $(KNET_COMMON_SRC) \
				  $(DATASTRUCTURES_SRC)

KNET_SYSCALL_SRC=\
				   $(KNET_COMMON_SRC) \
				   $(DATASTRUCTURES_SRC)

MYCFLAGS=\
		 -DHAVE_REMOTE_LOG \
		 -DHAVE_KMGMT \
		 -DHAVE_IF_STATS \
		 -DHAVE_ROUTE_STATS

AM_LDFLAGS = -lxml2 -lpthread
AM_CFLAGS = -I/usr/include/libxml2 $(MYCFLAGS)

kens_LDADD = -L. -liniparser
kens_SOURCES = misc.c \
			   $(KNET_KERNEL_SRC) \
			   $(KXML_SRC) \
			   $(KMGMT_SRC) \
			   $(LOG_SRC)

kensctrl_LDADD = -L. -lkens 
kensctrl_SOURCES = kensctrl.c

ktcptest1_LDADD = -L. -lktcp -lkens
ktcptest1_SOURCES = AllTests.c CuTest.c KtcpTest.c KtcpTest1.c

ktcptest2_LDADD = -L. -lktcp -lkens
ktcptest2_SOURCES = AllTests.c CuTest.c KtcpTest.c KtcpTest2.c

ktcptest3_LDADD = -L. -lktcp -lkens
ktcptest3_SOURCES = AllTests.c CuTest.c KtcpTest.c KtcpTest3.c

ktcptest4_LDADD = -L. -lktcp -lkens
ktcptest4_SOURCES = AllTests.c CuTest.c KtcpTest.c KtcpTest4.c

libiniparser_a_SOURCES = $(INIPARSER_SRC)

libkens_a_SOURCES = ksocket.c \
					misc.c \
					$(INIPARSER_SRC) \
					$(KXML_SRC) \
					$(LOG_SRC) \
					$(DATASTRUCTURES_SRC) \
					$(KMGMT_SRC)

libktcp_a_SOURCES = $(KNET_SYSCALL_SRC)
