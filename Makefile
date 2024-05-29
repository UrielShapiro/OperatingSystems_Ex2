CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
TTT = Q1/ttt
Q2_mync = Q2/mync
Q3_mync = Q3/mync
Q4_mync = Q4/mync
Q6_mync = Q6/mync


all: $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync) $(Q6_mync)

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q2_mync): $(Q2_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q3_mync): $(Q3_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<	

$(Q4_mync): $(Q4_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q6_mync): $(Q6_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $< -lpthread


clean:
	rm -f *.o $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync) $(Q6_mync)


.SUFFIXES:
.PHONY: ttt
