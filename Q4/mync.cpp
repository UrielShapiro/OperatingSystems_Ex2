#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>

#define MAX_PORT_SIZE 6

int open_tcp_server(sockaddr_in *addr, std::vector<int> &sockets_arr)
{
    int server_sock = socket(addr->sin_family, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0)
    {
        throw std::runtime_error("Error opening a TCP server socket");
    }
    sockets_arr.push_back(server_sock);

    int reuse = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        throw std::runtime_error("Error setting socket option SO_REUSEADDR");
    }

    if (bind(server_sock, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        throw std::runtime_error("Error binding the TCP server socket");
    }
    if (listen(server_sock, 1) < 0)
    {
        throw std::runtime_error("Error listening on server socket");
    }
    struct sockaddr client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_socket = accept(server_sock, &client_addr, &client_addr_len);
    if (client_socket < 0)
    {
        throw std::runtime_error("Error accepting client");
    }
    sockets_arr.push_back(client_socket);

    return client_socket;
}

int open_udp_server(sockaddr_in *addr, std::vector<int> &sockets_arr)
{
    int server_sock = socket(addr->sin_family, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock < 0)
    {
        throw std::runtime_error("Error opening a UDP server socket");
    }
    sockets_arr.push_back(server_sock);

    int reuse = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        throw std::runtime_error("Error setting socket option SO_REUSEADDR");
    }
    if (bind(server_sock, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        throw std::runtime_error("Error binding the UDP server socket");
    }
    return server_sock;
}

int open_udp_client(sockaddr_in *server_addr, std::vector<int> &sockets_arr)
{
    int client_sock = socket(server_addr->sin_family, SOCK_DGRAM, IPPROTO_UDP);
    if (client_sock < 0)
    {
        throw std::runtime_error("Error opening a UDP client socket");
    }
    sockets_arr.push_back(client_sock);

    if (connect(client_sock, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0)
    {
        throw std::runtime_error("Error connecting to the server socket");
    }

    return client_sock;
}

int open_tcp_client(sockaddr_in *server_address, std::vector<int> &sockets_arr)
{
    int client_sock = socket(server_address->sin_family, SOCK_STREAM, IPPROTO_TCP);
    if (client_sock < 0)
    {
        throw std::runtime_error("Error opening a client socket");
    }
    sockets_arr.push_back(client_sock);

    if (connect(client_sock, (struct sockaddr *)server_address, sizeof(*server_address)) < 0)
    {
        throw std::runtime_error("Error connecting to the server socket");
    }

    return client_sock;
}

void print_usage(char *program_name)
{
    std::cerr << "Usage: " << program_name << " -e \"<command>\" [-(i|o|b) UDP/TCP(C<IP or HOSTNAME>,<PORT>|S<PORT>)]" << std::endl;
}

enum protocol
{
    CONN_TCP,
    CONN_UDP
};

typedef struct
{
    struct sockaddr_in addr;
    protocol prot;
    bool is_server;
} connection;

connection *parse_address(char *arg)
{
    if (strlen(arg) < 4)
    {
        throw std::invalid_argument("Argument is too short");
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    connection *result = (connection *)malloc(sizeof(connection));
    memset(result, 0, sizeof(*result));

    if (strncmp(arg, "TCP", 3) == 0)
    {
        result->prot = CONN_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    else if (strncmp(arg, "UDP", 3) == 0)
    {
        result->prot = CONN_UDP;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else
    {
        throw std::invalid_argument("Unkown protocol specifier");
    }

    char *hostname = NULL, *port = (char *)malloc(MAX_PORT_SIZE);

    hints.ai_family = AF_INET;       // TODO: Consider supporting IPv6
    hints.ai_flags |= AI_ADDRCONFIG; // Returns IPv6 addresses only if your PC is compatible.

    if (arg[3] == 'S')
    {
        if (strlen(arg + 4) < 1)
        {
            free(port);
            throw std::invalid_argument("No port provided in server specifier");
        }
        strncpy(port, arg + 4, MAX_PORT_SIZE);

        hints.ai_flags |= AI_PASSIVE;

        result->is_server = true;
    }
    else if (arg[3] == 'C')
    {
        char *comma = arg + 4;
        while (*comma != '\0' && *comma != ',')
            comma += 1;
        if (*comma == '\0')
        {
            free(port);
            throw std::invalid_argument("No comma seperator in client specifier");
        }
        if (strlen(comma + 1) < 1)
        {
            free(port);
            throw std::invalid_argument("No port provided in client specifier");
        }
        strncpy(port, comma + 1, MAX_PORT_SIZE);

        hostname = (char *)malloc(INET_ADDRSTRLEN); // IPv6: max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)

        if (comma == arg + 4)
        {
            free(port);
            free(hostname);
            throw std::invalid_argument("No IP provided in client specifier");
        }
        strncpy(hostname, arg + 4, comma - (arg + 4));

        result->is_server = false;
        hostname[comma - (arg + 4)] = '\0';
    }
    else
    {
        throw std::invalid_argument("Unkown connection type specifier");
    }

    struct addrinfo *addrinfo_ret;
    int error = getaddrinfo(hostname, port, &hints, &addrinfo_ret);
    if (error != 0)
    {
        free(port);
        free(hostname);
        throw std::runtime_error(gai_strerror(error));
    }

    memcpy(&result->addr, addrinfo_ret->ai_addr, sizeof(result->addr));

    freeaddrinfo(addrinfo_ret); // Freeing the addrinfo struct
    free(port);
    free(hostname);

    return result;
}

int setup_connection(connection *conn, std::vector<int> &sockets)
{
    switch (conn->prot)
    {
    case CONN_TCP:
        if (conn->is_server)
            return open_tcp_server(&conn->addr, sockets);
        else
            return open_tcp_client(&conn->addr, sockets);
    case CONN_UDP:
        if (conn->is_server)
            return open_udp_server(&conn->addr, sockets);
        else
            return open_udp_client(&conn->addr, sockets);
    default:
        throw std::domain_error("Invalid connection type");
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Not enough arguments provided" << std::endl;
        return 1;
    }

    connection *input = NULL;
    connection *output = NULL;
    connection *both = NULL;

    char *command = NULL;
    char c;
    while ((c = getopt(argc, argv, "e:i:o:b:t:")) != -1)
    {
        switch (c)
        {
        case 't':
            alarm(atoi(optarg));
            break;

        case 'e':
            command = optarg;
            break;

        case 'i':
            if (input != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have double specifier for input" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }
            if (both != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have specifier for input and for both" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }

            try
            {
                input = parse_address(optarg);
                if (input->prot == CONN_UDP && !input->is_server)
                    throw std::invalid_argument("Cannot use UDP client as input");
            }
            catch (const std::invalid_argument &e)
            {
                std::cerr << "Error in address argument: " << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
                return 1;
            }
            catch (const std::runtime_error &e)
            {
                std::cerr << "Error finding hostname: " << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
                return 1;
            }
            break;
        case 'o':
            if (output != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have double specifier for output" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }
            if (both != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have specifier for output and for both" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }
            try
            {
                output = parse_address(optarg);
                if (output->prot == CONN_UDP && output->is_server)
                    throw std::invalid_argument("Cannot use UDP server as output");
            }
            catch (const std::invalid_argument &e)
            {
                std::cerr << "Error in address argument: " << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
                return 1;
            }
            catch (const std::runtime_error &e)
            {
                std::cerr << "Error finding hostname: " << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
            }
            break;
        case 'b':
            if (both != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have double specifier for both" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }
            if (input != NULL || output != NULL)
            {
                print_usage(argv[0]);
                std::cerr << "Cannot have specifier for both and for input or output" << std::endl;
                free(output);
                free(input);
                free(both);
                return 1;
            }
            try
            {
                both = parse_address(optarg);
                if (both->prot == CONN_UDP)
                    throw std::invalid_argument("Cannot use UDP as both input and output");
            }
            catch (const std::invalid_argument &e)
            {
                std::cerr << "Error in address argument: " << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
                return 1;
            }
            catch (const std::runtime_error &e)
            {
                std::cerr << "Error finding hostname" << e.what() << std::endl;
                print_usage(argv[0]);
                free(output);
                free(input);
                free(both);
            }
            break;

        default:
            print_usage(argv[0]);
            std::cerr << "Unknown option: \'" << c << "\'" << std::endl;
            free(output);
            free(input);
            free(both);
            return 1;
        }
    }

    if (command == NULL)
    {
        print_usage(argv[0]);
        std::cerr << "ERROR: Command not found" << std::endl;
        free(output);
        free(input);
        free(both);
        return 1;
    }

    fflush(stdin);
    fflush(stdout);
    int input_fd = STDIN_FILENO, output_fd = STDOUT_FILENO;

    std::vector<int> sockets;

    if (both != NULL)
    {
        try
        {
            input_fd = output_fd = setup_connection(both, sockets);
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << "Error opening connection: " << e.what() << std::endl;
            free(output);
            free(input);
            free(both);
            return 1;
        }
    }

    if (input != NULL)
    {
        try
        {
            input_fd = setup_connection(input, sockets);
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << "Error opening connection: " << e.what() << std::endl;
            free(output);
            free(input);
            free(both);
            return 1;
        }
    }

    if (output != NULL)
    {
        try
        {
            output_fd = setup_connection(output, sockets);
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << "Error opening connection: " << e.what() << std::endl;
            free(output);
            free(input);
            free(both);
            return 1;
        }
    }

    if (dup2(input_fd, STDIN_FILENO) < 0)
    {
        perror("Error duping input file descriptor");
        free(output);
        free(input);
        free(both);
        return 1;
    }
    if (dup2(output_fd, STDOUT_FILENO) < 0)
    {
        perror("Error duping output file descriptor");
        free(output);
        free(input);
        free(both);
        return 1;
    }

    if (system(command) < 0)
    {
        perror("ERROR: On command execution (system(3))");
        std::cerr << "INFO: Command was \"" << command << "\"" << std::endl;
        free(output);
        free(input);
        free(both);
        return 1;
    }

    for (int socket : sockets)
    {
        close(socket);
    }

    return 0;
}
