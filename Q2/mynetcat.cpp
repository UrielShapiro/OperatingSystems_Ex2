#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ARG_MAX 4096
#define ttt_path "../tic_tac_toe"
#define PIPE_READ_END 0
#define PIPE_WRITE_END 1
#define TMP_NUM 1 << 10

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Not enough arguments provided" << std::endl;
        std::cerr << "Usage: ./mync -e <program name> <program strategy>" << std::endl;
        return 1;
    }

    std::string programName;
    std::string strategy;
    size_t i = 0;

    // Parse the arguments
    while (i < (size_t)argc)
    {
        if (!strcmp(argv[i], "-e"))
        {
            try
            {
                programName = strtok(argv[++i], " ");
                strategy = strtok(NULL, " ");
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Not enough parameters" << std::endl;
            }
        }
        i++;
    }

    if (!programName.compare(" ttt"))
    {
        std::cerr << "Arguments provided are not valid" << std::endl;
        std::cerr << "Program name: " << programName << std::endl;
        return 1;
    }
    if (strategy.length() < 9)
    {
        std::cerr << "Arguments provided are not valid" << std::endl;
        std::cerr << "strategy length does not contain all of the numbers between 1-9" << std::endl;
        return 1;
    }

#ifdef DEBUG
    std::cout << "Program Name:" << programName << std::endl;
    std::cout << "Strategy:";
    for (char &s : strategy)
    {
        std::cout << s;
    }
    std::cout << std::endl;
#endif

    fflush(STDIN_FILENO);
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        std::cerr << "Error creating pipe" << std::endl;
        return 1;
    }

    std::string program = std::string(ttt_path) + "/" + programName;

    if (fork() == 0)
    {
        close(pipefd[PIPE_READ_END]);                          // Close the read end
        if (dup2(pipefd[PIPE_WRITE_END], STDOUT_FILENO) == -1) // Redirect the stdout to the write end of the pipe
        {
            std::cerr << "Error redirecting stdout to the pipe" << std::endl;
            exit(1);
        }
        close(pipefd[PIPE_WRITE_END]);                    // Close the write end becuase it is no longer needed
        execlp(program.c_str(), program.c_str(), strategy.c_str(), (char *)NULL); // Execute the ttt with the strategy provided

        std::cerr << "execlp(3)" << std::endl; // If reached here, execlp has failed
        exit(1);
    }

    // Parent proccess:
    close(pipefd[PIPE_WRITE_END]); // Close unused end
    char buffer[TMP_NUM];          // TODO: Change TMP_NUM to something that make sense.
    ssize_t bytes_received = 0;

    while ((bytes_received = read(pipefd[PIPE_READ_END], buffer, TMP_NUM)) > 0)
    {
        buffer[bytes_received] = '\0';
        std::cout << buffer;
    }
    close(pipefd[PIPE_READ_END]);
    wait(NULL);

    return 0;
}