BINS = gss-server-c gss-client-c

SRC = gss-server.c gss-client.c gss-misc.c

OBJS = $(SRC:.c=.o)

all: $(BINS)

gss-server-c: gss-server.o gss-misc.o
	$(CC) -o $@ $^ -lgssapi_krb5

gss-client-c: gss-client.o gss-misc.o
	$(CC) -o $@ $^ -lgssapi_krb5
