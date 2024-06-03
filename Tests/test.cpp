#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN // Uses the main function from doctest.h
#include "doctest.h"
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define SLEEP_TIME 2
#define PIPE_READ_END 0
#define PIPE_WRITE_END 1
#define PROGRAM_NAME "Q6/mync"
#define MAX_COMMAND_LENGTH 100

void open_server(char *connection, const char *filename)
{
    char runthis[MAX_COMMAND_LENGTH] = {0};
    snprintf(runthis, MAX_COMMAND_LENGTH, "socat -t1 - %s < %s", connection, filename);
    if (fork() == 0)
    {
        system(runthis);
        exit(0);
    }
}

void open_client(std::string connection, std::string filename)
{
    std::string runthis = "socat - " + connection + " < " + filename;
    system(runthis.c_str());
}

void run_command(char *const *argv, char *output = NULL, unsigned int timeout = 0)
{
    pid_t child;
    if ((child = fork()) == 0)
    {
        if (output)
        {
            int file = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            dup2(file, STDOUT_FILENO);
        }
        execvp(PROGRAM_NAME, argv);
    }
    if (timeout > 0)
    {
        sleep(timeout);
        kill(child, SIGKILL);
    }
    waitpid(child, NULL, 0);
}

TEST_CASE("-i")
{
    SUBCASE("-i TCPS")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "TCPS5000";
        char *const connection2 = "TCP:localhost:5000";
        char *const output = "Tests/outputs/test1.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, output, SLEEP_TIME);
            exit(0);
        }
        usleep(500000);
        open_client(connection2, "Tests/inputs/test1.txt");

        CHECK(system("cmp Tests/outputs/test1.txt Tests/expected_output/test1.txt") == 0);
    }

    SUBCASE("-i TCPC")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "TCPClocalhost,5000";
        char *const connection2 = "TCP-LISTEN:5000,reuseaddr";
        char *const output = "Tests/outputs/test4.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        open_server(connection2, "Tests/inputs/test4.txt");
        usleep(500000);
        if (fork() == 0)
        {
            run_command(argv, output, SLEEP_TIME);
            exit(0);
        }
        usleep(500000);

        CHECK(system("cmp Tests/outputs/test4.txt Tests/expected_output/test4.txt") == 0);
    }

    SUBCASE("-i UDPS")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "UDPS4000";
        char *const connection2 = "UDP:localhost:4000";
        char *const output = "Tests/outputs/test2.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, output, SLEEP_TIME);
            exit(0);
        }
        usleep(500000);
        open_client(connection2, "Tests/inputs/test2.txt");

        CHECK(system("cmp Tests/outputs/test2.txt Tests/expected_output/test2.txt") == 0);
    }

    SUBCASE("-i UDSSS")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "UDSSS/tmp/udss";
        char *const connection2 = "UNIX-CONNECT:/tmp/udss";
        char *const output = "Tests/outputs/test3.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, output, SLEEP_TIME);
            exit(0);
        }
        usleep(500000);
        open_client(connection2, "Tests/inputs/test3.txt");

        CHECK(system("cmp Tests/outputs/test3.txt Tests/expected_output/test3.txt") == 0);
    }

    SUBCASE("-i UDSSD")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "UDSSD/tmp/udss";
        char *const connection2 = "UNIX-CONNECT:/tmp/udsd";
        char *const output = "Tests/outputs/test3.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, output, SLEEP_TIME);
            exit(0);
        }
        usleep(500000);
        open_client(connection2, "Tests/inputs/test3.txt");

        CHECK(system("cmp Tests/outputs/test3.txt Tests/expected_output/test3.txt") == 0);
    }
}

// TEST_CASE("-i TCPC")
// {
//     char *const command = "cat";
//     char *const connection_type = "-i ";
//     char *const connection1 = "TCPS5000";
//     char *const connection2 = "localhost 5000";
//     char *const port = "5000";
//     char *const output = "outputs/output1.txt";

//     char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

//     if (fork() == 0)
//     {
//         open_server()
//     }
// }

// int main()
// {

// for (file in input_dir)
//     run(file)
//     compare(output, output_dir/file)

// int pipe_fd[2];

// if (pipe(pipe_fd) == -1)
// {
//     strerror(errno);
//     std::cerr << "Error creating pipe" << std::endl;
//     exit(1);
// }

// if (fork() == 0)
// {
//     close(pipe_fd[PIPE_READ_END]);

//     dup2(pipe_fd[PIPE_WRITE_END], STDOUT_FILENO);
//     close(pipe_fd[PIPE_WRITE_END]);

//     char *arg = "-e \"ttt 123456789\" -i TCPS5000";

//     execlp(PROGRAM_NAME, arg, NULL);
//     std::cerr << "ERROR in execlp" << std::endl;
//     exit(1);
// }
// else
// {
//     close(pipe_fd[PIPE_WRITE_END]);

//     dup2(pipe_fd[PIPE_READ_END], STDIN_FILENO);
//     close(pipe_fd[PIPE_READ_END]);

//     if (fork() == 0)
//     {
//         system("nc -l -p 5000");
//         alarm(5);
//     }

//     char *strat = "987654321";
//     size_t i = 0;
//     while (i < strlen(strat) && write(pipe_fd[PIPE_WRITE_END], strat + i++, 1) != -1)
//         ;

//     wait(NULL);
// }

//     return 0;
// }