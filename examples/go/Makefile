BINS = gss-client-go gss-server-go

all: $(BINS)

gss-client-go: gss-client/gss-client.go
	go build -o $@ $^ 

gss-server-go: gss-server/gss-server.go
	go build -o $@ $^ 
