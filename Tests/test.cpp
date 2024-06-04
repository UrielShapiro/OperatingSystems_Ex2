#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN // Uses the main function from doctest.h
#include "doctest.h"
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define SLEEP_TIME 2
#define USLEEP_TIME 20000
#define PIPE_READ_END 0
#define PIPE_WRITE_END 1
#define PROGRAM_NAME "Q6/mync"
#define MAX_COMMAND_LENGTH 256

void run_socat(char *connection, const char *command)
{
    char runthis[MAX_COMMAND_LENGTH] = {0};
    snprintf(runthis, MAX_COMMAND_LENGTH, "socat -t%d %s %s", SLEEP_TIME, connection, command);
    std::cout << runthis << std::endl;
    if (fork() == 0)
    {
        system(runthis);
        exit(0);
    }
}

void run_command(char *const *argv, char *output = NULL, char *input = NULL, unsigned int timeout = 0)
{
    int file;
    pid_t child;
    if ((child = fork()) == 0)
    {
        if (output)
        {
            file = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644); // 0644 sets the permissions
            dup2(file, STDOUT_FILENO);
        }
        if (input)
        {
            file = open(input, O_RDONLY); // 0644 sets the permissions
            dup2(file, STDIN_FILENO);
        }
        execvp(PROGRAM_NAME, argv);
    }
    if (timeout > 0)
    {
        sleep(timeout);
        kill(child, SIGALRM);
    }
    int wstatus;
    waitpid(child, &wstatus, 0);
    CHECK(WIFEXITED(wstatus));
    CHECK(WEXITSTATUS(wstatus) == 0);
    close(file);
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
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);
        run_socat(connection2, "OPEN:Tests/inputs/test1.txt");
        usleep(USLEEP_TIME);

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

        run_socat(connection2, "OPEN:Tests/inputs/test4.txt");
        usleep(USLEEP_TIME);
        if (fork() == 0)
        {
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);

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
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);
        run_socat(connection2, "OPEN:Tests/inputs/test2.txt");
        usleep(USLEEP_TIME);

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
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);
        run_socat(connection2, "OPEN:Tests/inputs/test3.txt");
        usleep(USLEEP_TIME);

        CHECK(system("cmp Tests/outputs/test3.txt Tests/expected_output/test3.txt") == 0);
    }

    SUBCASE("-i UDSSD")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "UDSSD/tmp/udsd";
        char *const connection2 = "UNIX-SENDTO:/tmp/udsd";
        char *const output = "Tests/outputs/test5.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);
        run_socat(connection2, "Tests/inputs/test5.txt");
        usleep(USLEEP_TIME);

        CHECK(system("cmp Tests/outputs/test5.txt Tests/expected_output/test5.txt") == 0);
    }

    SUBCASE("-i UDSCS")
    {
        char *const command = "cat";
        char *const connection_type = "-i";
        char *const connection1 = "UDSCS/tmp/udsc";
        char *const connection2 = "UNIX-LISTEN:/tmp/udsc";
        char *const output = "Tests/outputs/test6.txt";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        run_socat(connection2, "OPEN:Tests/inputs/test6.txt");
        usleep(USLEEP_TIME);
        if (fork() == 0)
        {
            run_command(argv, output, NULL, SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);

        CHECK(system("cmp Tests/outputs/test6.txt Tests/expected_output/test6.txt") == 0);
    }
}

TEST_CASE("-o")
{
    SUBCASE("-o TCPS")
    {
        char *const command = "cat";
        char *const connection_type = "-o";
        char *const connection1 = "TCPS6000";
        char *const connection2 = "TCP:localhost:6000";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

        if (fork() == 0)
        {
            run_command(argv, NULL, "Tests/inputs/test7.txt", SLEEP_TIME);
            exit(0);
        }
        usleep(USLEEP_TIME);
        run_socat(connection2, "OPEN:Tests/outputs/test7.txt,creat,trunc");
        usleep(10 * USLEEP_TIME);

        CHECK(system("cmp Tests/outputs/test7.txt Tests/expected_output/test7.txt") == 0);
    }

    SUBCASE("-o TCPC")
    {
        char *const command = "cat";
        char *const connection_type = "-o";
        char *const connection1 = "TCPClocalhost,6000";
        char *const connection2 = "TCP-LISTEN:6000,reuseaddr";

        char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};
        
        run_socat(connection2, "OPEN:Tests/outputs/test8.txt,creat,trunc");
        usleep(USLEEP_TIME);
        if (fork() == 0)
        {
            run_command(argv, NULL, "Tests/inputs/test8.txt", SLEEP_TIME);
            exit(0);
        }
        usleep(10 * USLEEP_TIME);

        CHECK(system("cmp Tests/outputs/test8.txt Tests/expected_output/test8.txt") == 0);
    }

    // SUBCASE("-i UDPS")
    // {
    //     char *const command = "cat";
    //     char *const connection_type = "-i";
    //     char *const connection1 = "UDPS4000";
    //     char *const connection2 = "UDP:localhost:4000";
    //     char *const output = "Tests/outputs/test2.txt";

    //     char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

    //     if (fork() == 0)
    //     {
    //         run_command(argv, output, SLEEP_TIME);
    //         exit(0);
    //     }
    //     usleep(500000);
    //     run_socat(connection2, "Tests/inputs/test2.txt");

    //     CHECK(system("cmp Tests/outputs/test2.txt Tests/expected_output/test2.txt") == 0);
    // }

    // SUBCASE("-i UDSSS")
    // {
    //     char *const command = "cat";
    //     char *const connection_type = "-i";
    //     char *const connection1 = "UDSSS/tmp/udss";
    //     char *const connection2 = "UNIX-CONNECT:/tmp/udss";
    //     char *const output = "Tests/outputs/test3.txt";

    //     char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

    //     if (fork() == 0)
    //     {
    //         run_command(argv, output, SLEEP_TIME);
    //         exit(0);
    //     }
    //     usleep(500000);
    //     run_socat(connection2, "Tests/inputs/test3.txt");

    //     CHECK(system("cmp Tests/outputs/test3.txt Tests/expected_output/test3.txt") == 0);
    // }

    // SUBCASE("-i UDSSD")
    // {
    //     char *const command = "cat";
    //     char *const connection_type = "-i";
    //     char *const connection1 = "UDSSD/tmp/udsd";
    //     char *const connection2 = "UNIX-SENDTO:/tmp/udsd";
    //     char *const output = "Tests/outputs/test5.txt";

    //     char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

    //     if (fork() == 0)
    //     {
    //         run_command(argv, output, SLEEP_TIME);
    //         exit(0);
    //     }
    //     usleep(500000);
    //     run_socat(connection2, "Tests/inputs/test5.txt");

    //     CHECK(system("cmp Tests/outputs/test5.txt Tests/expected_output/test5.txt") == 0);
    // }

    // SUBCASE("-i UDSCS")
    // {
    //     char *const command = "cat";
    //     char *const connection_type = "-i";
    //     char *const connection1 = "UDSCS/tmp/udsc";
    //     char *const connection2 = "UNIX-LISTEN:/tmp/udsc";
    //     char *const output = "Tests/outputs/test6.txt";

    //     char *const argv[] = {PROGRAM_NAME, "-e", command, connection_type, connection1, NULL};

    //     run_socat(connection2, "Tests/inputs/test6.txt");
    //     usleep(500000);
    //     if (fork() == 0)
    //     {
    //         run_command(argv, output, SLEEP_TIME);
    //         exit(0);
    //     }
    //     usleep(500000);

    //     CHECK(system("cmp Tests/outputs/test6.txt Tests/expected_output/test6.txt") == 0);
    // }
}

TEST_CASE("invalid inputs")
{
    SUBCASE("unkown executable")
    {
        CHECK(system(PROGRAM_NAME " -e ./nonexistant 2> /dev/null") != 0);
    }
    SUBCASE("double connections")
    {
        CHECK(system(PROGRAM_NAME " -b TCPClocalhost,5000 -i UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -i TCPClocalhost,5000 -i UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPClocalhost,5000 -o UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -o TCPClocalhost,5000 -o UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPClocalhost,5000 -b UDPS3000 2> /dev/null") != 0);
    }
    SUBCASE("invalid connection specifiers")
    {
        CHECK(system(PROGRAM_NAME " -b HelloNezer 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b hi 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCP 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDP 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPP 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDPP 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDSS 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPC5000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPC,5000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPClocalhost, 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPClocalhost 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDSSP 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDSPS 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPS 2> /dev/null") != 0);
    }
    SUBCASE("timeout argument")
    {
        CHECK(system(PROGRAM_NAME " -t what 2> /dev/null") != 0);
    }
    SUBCASE("unkown argument")
    {
        CHECK(system(PROGRAM_NAME " -l 2> /dev/null") != 0);
    }
    SUBCASE("datagram limitations")
    {
        CHECK(system(PROGRAM_NAME " -b UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDPClocalhost,3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -o UDPS3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -i UDPClocalhost,3000 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDSSD/tmp/uds 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b UDSCD/tmp/uds 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -o UDSSD/tmp/uds 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -i UDSCD/tmp/uds 2> /dev/null") != 0);
    }
    SUBCASE("invalid port")
    {
        CHECK(system(PROGRAM_NAME " -b TCPS-5 2> /dev/null") != 0);
        CHECK(system(PROGRAM_NAME " -b TCPShi 2> /dev/null") != 0);
    }
    SUBCASE("unkown hostname")
    {
        CHECK(system(PROGRAM_NAME " -b TCPCwww.nezeristhebest.com,80 2> /dev/null") != 0);
    }
}