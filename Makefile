SRC= *.cc
HEAD= *.h
CXX= g++
FLAGS= -std=c++11 -pthread


#-DNDEBUG

default: myldap

myldap: $(HEAD) $(SRC)
	$(CXX) $(FLAGS) $^ -o myldap

debug: $(HEAD) $(SRC)
	$(CXX) $(FLAGS) -DNDEBUG $^ -o myldap

clean:
	rm myldap