CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
TTT = tic_tac_toe/ttt
Q2_mync = Q2/mync
Q3_mync = Q3/mync
Q4_mync = Q4/mync


all: $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync)

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q2_mync): $(Q2_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q3_mync): $(Q3_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<	

$(Q4_mync): $(Q4_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<
clean:
	rm -f *.o $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync)

.SUFFIXES:
.PHONY: ttt
