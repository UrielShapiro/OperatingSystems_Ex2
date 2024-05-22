#include <iostream>
#include <vector>
#include <stdexcept>
#include <stdio.h>
#include <cstdint>
#include <cstring>

std::vector<uint8_t> extract_strategy(char *argument)
{
	size_t len = strlen(argument);
	if (len != 9) throw std::invalid_argument("input is not of length 9"); // a valid input must be of length 9
	bool digits[9] = { false }; // digits[i] says whether digit (i+1) has been encountered
	std::vector<uint8_t> result = std::vector<uint8_t>(9, 0);
	for (size_t i = 0; i < len; ++i)
	{
		char c = argument[i];
		if (c < '1' || c > '9') // make sure character is a valid digit
			throw std::invalid_argument("input contains character which is not a digit from 1 to 9");
		uint8_t digit = c - '0';
		if (digits[digit - 1]) // make sure digit is not a duplicate, also insures all digits will appear
			throw std::invalid_argument("digit appears twice in the input");
		result.push_back(digit); // add the digit to the last place in the strategy
		digits[digit - 1] = true;
	}
	return result;
}

void print_usage(char *program_name)
{
	fprintf(stderr, "USAGE: %s STRATEGY\n", program_name);
	fprintf(stderr, "STRATEGY must include only digits between 1 and 9, and each one exactly once\n");
}

enum Square { EMPTY = 0, X, O };

using Board = Square[3][3];

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cerr << "Error: not enough argument" << std::endl;
		print_usage(argv[0]);
		return 1;
	}
	try
	{
		std::vector<uint8_t> strategy = extract_strategy(argv[1]);
	}
	catch (const std::invalid_argument &e)
	{
		std::cerr << "Error in strategy: " << e.what() << std::endl;
		print_usage(argv[0]);
		return 1;
	}

	Board board = { EMPTY };

	return 0;
}
