CXX = g++
CXX_FLAGS = -Wall -Wextra -ggdb
TTT = tic_tac_toe/ttt

ttt: $(TTT)

$(TTT): $(TTT).cpp
	$(CXX) $(CXX_FLAGS) -o $@ $<

clean:
	rm -f $(TTT)

.SUFFIXES:
.PHONY: ttt
