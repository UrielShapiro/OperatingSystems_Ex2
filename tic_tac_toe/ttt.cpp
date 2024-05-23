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
	std::vector<uint8_t> result = std::vector<uint8_t>();
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

#define AI_MARK X

#define BOARD_SIZE 3

using Board = Square[BOARD_SIZE][BOARD_SIZE];

#define COORDS_TO_SPOT(x, y) (1 + (x) + BOARD_SIZE*(y))
#define SPOT_FROM_BOARD(b, s) ((b)[((s)-1) % BOARD_SIZE][((s)-1) / BOARD_SIZE])

void print_board(Board board)
{
	std::cout << "┌";
	for (size_t x = 0; x < BOARD_SIZE - 1; ++x)
	{
		std::cout << "─┬";
	}
	std::cout << "─┐";
	std::cout << std::endl;
	for (size_t y = 0; y < BOARD_SIZE; ++y)
	{
		for (size_t x = 0; x < BOARD_SIZE; ++x)
		{
			 std::cout << "│";
			 if (board[x][y] == X) std::cout << "\e[31mX\e[0m";
			 else if (board[x][y] == O) std::cout << "\e[32mO\e[0m";
			 else if (board[x][y] == EMPTY) std::cout << COORDS_TO_SPOT(x, y);
			 else throw std::domain_error("board spot is not a valid value");
			 if (x == BOARD_SIZE - 1) std::cout << "│";
		}
		std::cout << std::endl;
		if (y < BOARD_SIZE - 1)
		{
			std::cout << "├";
			for (size_t x = 0; x < BOARD_SIZE; ++x)
			{
				std::cout << "─";
				if (x < BOARD_SIZE - 1) std::cout << "┼";
			}
			std::cout << "┤";
			std::cout << std::endl;
		}
	}
	std::cout << "└";
	for (size_t x = 0; x < BOARD_SIZE - 1; ++x)
	{
		std::cout << "─┴";
	}
	std::cout << "─┘";
	std::cout << std::endl;
}

void reset_board(Board board)
{
	for (size_t y = 0; y < BOARD_SIZE; ++y)
		for (size_t x = 0; x < BOARD_SIZE; ++x)
			board[x][y] = EMPTY;
}

// performs a move according to the strategy, return whether a mark was placed, if false the board is full
bool ai_move(Board board, std::vector<uint8_t> strategy)
{
	for (size_t i = 0; i < BOARD_SIZE * BOARD_SIZE; ++i)
	{
		uint8_t spot = strategy[i];
		if (SPOT_FROM_BOARD(board, spot) == EMPTY)
		{
			SPOT_FROM_BOARD(board, spot) = AI_MARK;
			return true;
		}
	}
	return false; // we went through all spots and didn't find an empty one
}

enum GameResult { ONGOING, DRAW, X_WIN, O_WIN };
GameResult win_of(Square s)
{
	switch (s)
	{
	case X: return X_WIN;
	case O: return O_WIN;
	case EMPTY: throw std::domain_error("win_of was passed EMPTY");
	default: throw std::domain_error("win_of was passed illegal Square value");
	}
}

GameResult check_result(Board b)
{
	for (size_t y = 0; y < BOARD_SIZE; ++y)
	{
		if (b[0][y] == EMPTY) continue;
		Square s = b[0][y];
		bool line = true;
		for (size_t x = 1; line && x < BOARD_SIZE; ++x)
		{
			if (b[x][y] != s) line = false;
		}
		if (line) return win_of(s);
	}

	for (size_t x = 0; x < BOARD_SIZE; ++x)
	{
		if (b[x][0] == EMPTY) continue;
		Square s = b[x][0];
		bool line = true;
		for (size_t y = 1; line && y < BOARD_SIZE; ++y)
		{
			if (b[x][y] != s) line = false;
		}
		if (line) return win_of(s);
	}

	{
		Square s = b[0][0];
		if (s != EMPTY)
		{
			bool line = true;
			for (size_t i = 1; line && i < BOARD_SIZE; ++i)
			{
				if (b[i][i] != s) line = false;
			}
			if (line) return win_of(s);
		}
	}

	{
		Square s = b[0][BOARD_SIZE - 1];
		if (s != EMPTY)
		{
			bool line = true;
			for (size_t i = 1; line && i < BOARD_SIZE; ++i)
			{
				if (b[i][BOARD_SIZE - i - 1] != s) line = false;
			}
			if (line) return win_of(s);
		}
	}

	for (size_t x = 0; x < BOARD_SIZE; ++x)
		for (size_t y = 0; y < BOARD_SIZE; ++y)
			if (b[x][y] == EMPTY) return ONGOING;
	
	return DRAW;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cerr << "Error: not enough argument" << std::endl;
		print_usage(argv[0]);
		return 1;
	}

	std::vector<uint8_t> strategy;
	try { strategy = extract_strategy(argv[1]); }
	catch (const std::invalid_argument &e)
	{
		std::cerr << "Error in strategy: " << e.what() << std::endl;
		print_usage(argv[0]);
		return 1;
	}

	Board board;
	reset_board(board);

	GameResult result;
	bool ai_turn = true;
	while ((result = check_result(board)) == ONGOING)
	{
		if (ai_turn)
		{
			ai_move(board, strategy);
		}
		else
		{
			bool chose = false;
			while (!chose)
			{
				std::cout << "Enter your choice of square: ";
				std::string line;
				std::getline(std::cin, line);
				int choice;
				try { choice = stoi(line); }
				catch (const std::invalid_argument &e)
				{
					std::cout << "Please enter a number." << std::endl;
					continue;
				}
				if (choice < 1 || choice > 9)
				{
					std::cout << "Invalid square number entered, please enter a digit from 1 to 9." << std::endl;
					continue;
				}
				if (SPOT_FROM_BOARD(board, choice) != EMPTY)
				{
					std:: cout << "This sqaure is taken, please choose another sqaure." << std::endl;
					continue;
				}
				SPOT_FROM_BOARD(board, choice) = O;
				chose = true;
			}
		}
		ai_turn = !ai_turn;
		print_board(board);
	}
	switch (result)
	{
	case O_WIN: std::cout << "You win!" << std::endl; break;
	case X_WIN: std::cout << "I win!" << std::endl; break;
	case DRAW: std::cout << "We drew!" << std::endl; break;
	case ONGOING: throw std::domain_error("result is ONGOING after game finish");
	default: throw std::domain_error("invalid GameResult value");
	}

	return 0;
}
