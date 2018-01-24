
CC =	cc
CONFIG = llvm-config
CFLAGS = $(shell ${CONFIG} --cflags) -std=c++11 -Wno-strict-aliasing
LINK = $(CC)
LDFLAGS = -fPIC -fvisibility-inlines-hidden -fno-common -g -shared

%.o:	%.cc
	$(CC) $(CFLAGS) -o $@ -c $<

ngx-ast.so:	ngx-ast.o
	$(LINK) $(LDFLAGS) -o $@ $<

all:	ngx-ast.so

clean:
	rm -f *.o *~ *.so
