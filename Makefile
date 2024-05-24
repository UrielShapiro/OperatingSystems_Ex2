CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
TTT = tic_tac_toe/ttt
mynetcat = Q2/mynetcat
mync = Q2/mync

all: ttt $(mync)

ttt: $(TTT)

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(mync): $(mynetcat).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

clean:
	rm -f *.o $(TTT) $(mync)

.SUFFIXES:
.PHONY: ttt
