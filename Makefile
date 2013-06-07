CFLAGS = -Wall -DMED_DEBUG -O0 -static -fprofile-arcs -ftest-coverage

# Should be equivalent to your list of C files, if you don't build selectively
SRC=$(wildcard *.c)

test: $(SRC)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm test
	rm *.o


