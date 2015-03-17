.SUFFIXES : .c .o .result


CC = gcc
CFLAGS = -g -D_BSD_SOURCE -DDISABLE_LOG -O0 -fPIC -Wall -DUSE_FORK
LIBS = -lcunit
TEST_SRC = $(wildcard test*.c)

all: testktcp

clean:
	rm -f testktcp *.o *.pcap *.report grade

#ktcp_reference.o: lib/ktcp_reference.c ../src/linked_list.h ../src/ktcp_easy_impl.h ../src/ktcp_easy_lib.h
#	$(CC) $(CFLAGS) -c -I ../src lib/ktcp_reference.c $(LIBS)

ktcp_test_lib.o: lib/ktcp_test_lib.c lib/ktcp_test_lib.h ../src/linked_list.h ../src/ktcp_easy_impl.h ../src/ktcp_easy_lib.h
	$(CC) $(CFLAGS) -c -I ../src -I . -I lib lib/ktcp_test_lib.c $(LIBS)

linked_list.o: ../src/linked_list.h ../src/linked_list.c
	$(CC) $(CFLAGS) -c -I ../src ../src/linked_list.c $(LIBS)

testktcp: $(TEST_SRC) testktcp.h ktcp_test_lib.o ktcp_reference.o linked_list.o ../src/ktcp_easy_impl.c
	$(CC) $(CFLAGS) -o $@ -I ../src -I . -I lib $(TEST_SRC) ../src/ktcp_easy_impl.c ktcp_test_lib.o ktcp_reference.o linked_list.o $(LIBS)
