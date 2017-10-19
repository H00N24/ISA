default: myldap

myldap: myldap.cc server.h server.cc ldap_fsm.h ldap_fsm.cc
	g++ myldap.cc server.h server.cc ldap_fsm.h ldap_fsm.cc -std=c++11 -o myldap

clean:
	rm myldap