BINS = SampleClient.class   SampleServer.class

.SUFFIXES: .java .class

all: $(BINS)

.java.class:
	javac -g  $<

.PHONY: run-client
run-client:
	java -Dsun.security.krb5.debug=true   -Djavax.security.auth.useSubjectCredsOnly=false -Djava.security.krb5.conf=../testvectors/krb5.conf -Djava.security.auth.login.config=./jaas.conf   SampleClient rack@foo.golang-auth.io  localhost 1234

.PHONY: run-server
run-server:
	java -Dsun.security.krb5.debug=true   -Djavax.security.auth.useSubjectCredsOnly=false -Djava.security.krb5.conf=../testvectors/krb5.conf -Djava.security.auth.login.config=./jaas.conf   SampleServer 1234
