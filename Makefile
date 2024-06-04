CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
GCOV_FLAGS = -ftest-coverage -fprofile-arcs
TTT = Q1/ttt
Q2_mync = Q2/mync
Q3_mync = Q3/mync
Q4_mync = Q4/mync
Q6_mync = Q6/mync
Test = Tests/test

all: $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync) $(Q6_mync) $(Test)

gcov: $(Test) $(Q6_mync)
	-mkdir Tests/outputs
	$(Test)
	gcov mync.cpp
	cat mync.cpp.gcov

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q2_mync): $(Q2_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q3_mync): $(Q3_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<	

$(Q4_mync): $(Q4_mync).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

$(Q6_mync): $(Q6_mync).cpp
	$(CXX) $(GCOV_FLAGS) $(CXX_FLAGS) -o $@ $< -lpthread

$(Test): $(Test).o
	$(CXX) $(GCOV_FLAGS) $(CXX_FLAGS) -o $@ $<

$(Test).o: $(Test).cpp
	$(CXX) -Wno-write-strings $(CXX_FLAGS) -c -o $@ $<

clean:
	rm -f *.o $(TTT) $(Q2_mync) $(Q3_mync) $(Q4_mync) $(Q6_mync) $(Test) *.gcov *.gcno *.gcda


.SUFFIXES:
.PHONY: gcov
