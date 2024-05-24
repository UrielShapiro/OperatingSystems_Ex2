CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
TTT = tic_tac_toe/ttt
Q2_mynetcat = Q2/mynetcat
Q2_mync = Q2/mync
Q3_mynetcat = Q3/mynetcat
Q3_mync = Q3/mync


all: ttt $(Q2_mync) $(Q3_mync)

ttt: $(TTT)

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q2_mync): $(Q2_mynetcat).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q3_mync): $(Q3_mynetcat).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<	

clean:
	rm -f *.o $(TTT) $(Q2_mync) $(Q3_mync)

.SUFFIXES:
.PHONY: ttt
