default: myldap

myldap: myldap.cc server.h server.cc
	g++ myldap.cc server.h server.cc -std=c++11 -o myldap

clean:
	rm myldap