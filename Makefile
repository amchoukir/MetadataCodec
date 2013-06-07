CFLAGS = -Wall -DMED_DEBUG

# Should be equivalent to your list of C files, if you don't build selectively
SRC=$(wildcard *.c)

#random:
#	gcc -Wall -O0 -g -o test  med.c med_decode.c  test_rand.c -DMED_DEBUG

dynamic:
	-rm *.o
	gcc -Wall -fPIC -c med.c med_decode.c
	gcc -shared -Wl,-soname,libmedenc.so.1 -o libmedenc.so.1.0   *.o
	ln -sf libmedenc.so.1.0 libmedenc.so.1
	ln -sf libmedenc.so.1.0 libmedenc.so

static:
	-rm *.o
	gcc -Wall -c med.c med_decode.c
	ar -cvq libmedenc.a *.o

libraries: dynamic static

strip: libraries
	strip --strip-all libmedenc*

test: $(SRC)
	gcc -o $@ $^ $(CFLAGS)

coverage:
	gcc -o $@ $^ $(CFLAGS) -O0 -static -fprofile-arcs -ftest-coverage

clean:
	-rm test
	-rm coverage
	-rm libmedenc*
	-rm *.o
	-rm *.gc*


