#include <iostream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>

#define ARG_MAX 4096
#define ttt_path "../tic_tac_toe"
#define PIPE_READ_END 0
#define PIPE_WRITE_END 1
#define TMP_NUM 1 << 10
#define MIN_PORT 1023

std::string *parse_client_server(char *input)
{
    bool server = input[3] == 'S' ? true : false;
    std::string *output = new std::string[3];
    if (server)
    {
        size_t position = 0;
        while (input[position] && !isdigit(input[position]))
        {
            position++;
        }
        std::string port = "";
        for (size_t j = 0; j < strlen(input + position) + 1; j++)
        {
            port += input[position + j];
        }
        output[0] = "Server";
        output[1] = port;
        return output;
    }
    else
    {
        std::string hostname = "";
        size_t position = 0;
        while (input[4 + position] && !isdigit(input[4 + position]))
        {
            position++;
        }
        std::string port = "";
        for (size_t j = 0; j < strlen(input + position) + 1; j++)
        {
            port += input[4 + position + j];
        }
        for (size_t j = 0; j < position; j++)
        {
            hostname += input[4 + j];
        }
        output[0] = "Client";
        output[1] = port;
        output[2] = hostname;
        return output;
    }
}

int openServer(unsigned short port)
{
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd == -1)
    {
        std::cerr << "Error: Failed to create socket." << std::endl;
        return 1;
    }

    // Bind the socket to an address and port
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Bind to any available network interface
    serverAddr.sin_port = htons(port);       // Use port 8080

    if (bind(serverfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error: Failed to bind socket." << std::endl;
        close(serverfd);
        exit(1);
    }
    return serverfd;
}

int openClient(std::string ip, unsigned short port)
{
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        std::cerr << "Error: Failed to create socket." << std::endl;
        return 1;
    }

    // Specify the server address and port
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port); // Server port number

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) <= 0)
    {
        std::cerr << "Error: Invalid address or address not supported." << std::endl;
        close(clientSocket);
        return 1;
    }

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error: Connection to the server failed." << std::endl;
        close(clientSocket);
        return 1;
    }
    return clientSocket;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Not enough arguments provided" << std::endl;
        std::cerr << "Usage: ./mync -e <program name> <program strategy>" << std::endl;
        return 1;
    }

    std::string programName = "";
    std::string strategy = "";
    unsigned short port = 0;
    std::string client_ip;
    bool c_or_s;                // False - Client, True - Server
    bool direct_input = false;  // For -i
    bool direct_output = false; // For -o
    std::string *data;
    size_t i = 0;

    pid_t parent_pid = getppid();

    // Parse the arguments
    while (i < (size_t)argc)
    {
        if (!strcmp(argv[i], "-e"))
        {
            try
            {
                programName = std::string(strtok(argv[++i], " "));
                strategy = std::string(strtok(argv[++i], " "));
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Not enough parameters" << std::endl;
            }
        }
        if (!strcmp(argv[i], "-i"))
        {
            try
            {
                data = parse_client_server(argv[++i]);
                c_or_s = data[0] == "Server" ? true : false;
                port = atoi(data[1].c_str());
                if (!c_or_s)
                {
                    client_ip = data[2];
                }

                direct_input = true;
#ifdef DEBUG
                if (c_or_s)
                {
                    std::cout << argv[i][position] << "Therefore, it is a server" << std::endl;
                }
                else
                {
                    std::cout << argv[i][position] << "Therefore, it is a client" << std::endl;
                }
                std::cout << "Port: " << port << std::endl;
#endif
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Not enough parameters" << std::endl;
            }

            if (fork() == 0)
            {
                break;
            }
        }
        if (!strcmp(argv[i], "-o"))
        {
            try
            {
                data = parse_client_server(argv[++i]);
                c_or_s = data[0] == "Server" ? true : false;
                port = atoi(data[1].c_str());
                if (!c_or_s)
                {
                    client_ip = data[2];
                }

                direct_output = true;

#ifdef DEBUG
                if (c_or_s)
                {
                    std::cout << argv[i][position] << "Therefore, it is a server" << std::endl;
                }
                else
                {
                    std::cout << argv[i][position] << "Therefore, it is a client" << std::endl;
                }
                std::cout << "Port: " << port << std::endl;
#endif
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Not enough parameters" << std::endl;
            }

            if (fork() == 0)
            {
                break;
            }
        }
        if (!strcmp(argv[i], "-b"))
        {
            try
            {
                data = parse_client_server(argv[++i]);
                c_or_s = data[0] == "Server" ? true : false;
                port = atoi(data[1].c_str());
                if (!c_or_s)
                {
                    client_ip = data[2];
                }

                direct_output = true;
                direct_input = true;
#ifdef DEBUG
                if (c_or_s)
                {
                    std::cout << argv[i][position] << "Therefore, it is a server" << std::endl;
                }
                else
                {
                    std::cout << argv[i][position] << "Therefore, it is a client" << std::endl;
                }
                std::cout << "Port: " << port << std::endl;
#endif
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Not enough parameters" << std::endl;
            }

            if (fork() == 0)
            {
                break;
            }
        }
        i++;
    }

    if (programName.compare(" ttt") == 0)
    {
        std::cerr << "Arguments provided are not valid" << std::endl;
        std::cerr << "Program name: " << programName << std::endl;
        return 1;
    }
    if (strategy.length() < 8)
    {
        std::cerr << "Arguments provided are not valid" << std::endl;
        std::cerr << "strategy length does not contain all of the numbers between 1-9" << std::endl;
        return 1;
    }

    std::string program = std::string(ttt_path) + "/" + programName;

    if (!data->empty() && getppid() != parent_pid)
    {
        delete[] data;

        // Opening a TCP Server
        if (c_or_s)
        {
            if (port < MIN_PORT)
            {
                std::cout << "Error: received port is incomplatible. Please enter a port above " << MIN_PORT << std::endl;
                exit(1);
            }
            int serverfd = openServer(port);

            // Start listening for incoming connections
            if (listen(serverfd, 1) == -1)
            {
                std::cerr << "Error: Failed to listen on socket." << std::endl;
                close(serverfd);
                return 1;
            }

            std::cout << "Server listening on port: " << port << "..." << std::endl;

            // Accept incoming connections
            struct sockaddr_in clientfd;
            socklen_t clientAddrLen = sizeof(clientfd);
            int clientSocket = accept(serverfd, (struct sockaddr *)&clientfd, &clientAddrLen);
            if (clientSocket == -1)
            {
                std::cerr << "Error: Failed to accept connection." << std::endl;
                close(serverfd);
                return 1;
            }

            if (direct_input && dup2(serverfd, STDIN_FILENO) == -1)
            {
                std::cerr << "Error redirecting stdin to the pipe" << std::endl;
                exit(1);
            }
            if (direct_output && dup2(serverfd, STDOUT_FILENO) == -1)
            {
                std::cerr << "Error redirecting stdout to the pipe" << std::endl;
                exit(1);
            }

            if (fork() == 0)
            {
                execlp(program.c_str(), program.c_str(), strategy.c_str(), (char *)NULL); // Execute the ttt with the strategy provided
                std::cerr << "Error running execlp on server" << std::endl;
                std::cerr << "execlp(3)" << std::endl;                                    // If reached here, execlp has failed
                exit(1);
            }
            wait(NULL);
        }

        // Opening a TCP Client
        if (!c_or_s)
        {
            int client = openClient(client_ip, port);

            if (direct_input && dup2(client, STDIN_FILENO) == -1)
            {
                std::cerr << "Error redirecting stdin to the pipe" << std::endl;
                exit(1);
            }
            if (direct_output && dup2(client, STDOUT_FILENO) == -1)
            {
                std::cerr << "Error redirecting stdout to the pipe" << std::endl;
                exit(1);
            }
            char buffer[TMP_NUM];
            ssize_t bytes_received;
            while ((bytes_received = recv(client, buffer, TMP_MAX - 1, 0)) > 0)
            {
                buffer[bytes_received] = '\0';
                std::cout << buffer;
            }
        }
    }
    else if(getppid() != parent_pid)
    {
        int pipefd[2];
        if (pipe(pipefd) == -1)
        {
            std::cerr << "Error creating pipe" << std::endl;
            return 1;
        }
        fflush(stdin);
        if (fork() == 0)
        {
            close(pipefd[PIPE_READ_END]);                          // Close the read end
            if (dup2(pipefd[PIPE_WRITE_END], STDOUT_FILENO) == -1) // Redirect the stdout to the write end of the pipe
            {
                std::cerr << "Error redirecting stdout to the pipe" << std::endl;
                exit(1);
            }
            close(pipefd[PIPE_WRITE_END]);                                            // Close the write end becuase it is no longer needed
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
    }
    wait(NULL);

    return 0;
}