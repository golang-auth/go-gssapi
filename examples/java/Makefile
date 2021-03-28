BINS = SampleClient.class   SampleServer.class

.SUFFIXES: .java .class

all: $(BINS)

.java.class:
	javac -g  $<

.PHONY: run-client
run-client:
	java -Djavax.security.auth.useSubjectCredsOnly=false -DKRB5CCNAME=/tmp/krb5cc_1000 -Dsun.security.krb5.debug=true -Djava.security.krb5.conf=/etc/krb5.conf -Djava.security.auth.login.config=./jaas.conf  SampleClient ldap/wellard.poptart.org localhost 1234 
