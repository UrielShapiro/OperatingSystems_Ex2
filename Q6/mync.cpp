#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <sys/un.h>
#include <threads.h>
#include <memory>
#include <signal.h>

// the maximum length of a string representing a port
#define MAX_PORT_SIZE 6
// used when there is no -e option, currently stored on stack so avoid sized too large
#define PIPER_BUFFER_SIZE 1024

class Cleanup
{
public:
    virtual void cleanup() = 0;
};

class SockCleanup : public Cleanup
{
    int sockfd;

public:
    SockCleanup(int fd) : sockfd(fd) {}
    void cleanup() override
    {
        close(sockfd);
    }
};

class UDSCleanup : public Cleanup
{
    char *filename;

public:
    UDSCleanup(char *file) : filename(file) {}
    void cleanup() override
    {
        unlink(filename);
        free(filename);
        filename = NULL;
    }
};

std::vector<std::unique_ptr<Cleanup>> to_cleanup;

int open_dgram_client(sockaddr *server_addr)
{
    int client_sock = socket(server_addr->sa_family, SOCK_DGRAM, 0);
    if (client_sock < 0)
    {
        throw std::runtime_error("Error opening a UDP client socket: " + std::string(strerror(errno)));
    }
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(client_sock)));
    socklen_t server_addr_len;
    if (server_addr->sa_family == AF_UNIX)
    {
        server_addr_len = sizeof(struct sockaddr_un);
    }
    else if (server_addr->sa_family == AF_INET)
    {
        server_addr_len = sizeof(struct sockaddr_in);
    }
    else
    {
        throw std::runtime_error("Unkown sa_family");
    }
    if (connect(client_sock, (struct sockaddr *)server_addr, server_addr_len) < 0)
    {
        throw std::runtime_error("Error connecting to the server socket: " + std::string(strerror(errno)));
    }

    return client_sock;
}

int open_stream_client(sockaddr *server_addr)
{
    int client_sock = socket(server_addr->sa_family, SOCK_STREAM, 0);
    if (client_sock < 0)
    {
        throw std::runtime_error("Error opening a client socket: " + std::string(strerror(errno)));
    }
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(client_sock)));
    socklen_t server_addr_len;
    if (server_addr->sa_family == AF_UNIX)
    {
        server_addr_len = sizeof(struct sockaddr_un);
    }
    else if (server_addr->sa_family == AF_INET)
    {
        server_addr_len = sizeof(struct sockaddr_in);
    }
    else
    {
        throw std::runtime_error("Unkown sa_family");
    }
    if (connect(client_sock, (struct sockaddr *)server_addr, server_addr_len) < 0)
    {
        throw std::runtime_error("Error connecting to the server socket: " + std::string(strerror(errno)));
    }

    return client_sock;
}

int open_stream_server(sockaddr *server_address)
{
    int server_sock = socket(server_address->sa_family, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        throw std::runtime_error("Error opening a server stream: " + std::string(strerror(errno)));
    }
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(server_sock)));

    if (server_address->sa_family == AF_UNIX)
    {
        to_cleanup.push_back(std::make_unique<UDSCleanup>(strdup(((sockaddr_un *)server_address)->sun_path)));
    }
    else
    {
        int reuse = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        {
            throw std::runtime_error("Error setting socket option SO_REUSEADDR: " + std::string(strerror(errno)));
        }
    }
    if (bind(server_sock, (struct sockaddr *)server_address, sizeof(*server_address)) < 0)
    {
        throw std::runtime_error("Error binding the server socket: " + std::string(strerror(errno)));
    }
    if (listen(server_sock, 1) < 0)
    {
        throw std::runtime_error("Error listening on server socket: " + std::string(strerror(errno)));
    }

    int client_socket = accept(server_sock, NULL, NULL);
    if (client_socket < 0)
    {
        throw std::runtime_error("Error accepting client: " + std::string(strerror(errno)));
    }
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(client_socket)));

    return client_socket;
}

int open_dgram_server(sockaddr *server_address)
{
    int server_sock = socket(server_address->sa_family, SOCK_DGRAM, 0);
    if (server_sock < 0)
    {
        throw std::runtime_error("Error opening a datagram server socket: " + std::string(strerror(errno)));
    }
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(server_sock)));

    if (server_address->sa_family == AF_UNIX)
    {
        to_cleanup.push_back(std::make_unique<UDSCleanup>(strdup(((sockaddr_un *)server_address)->sun_path)));
    }
    else
    {
        int reuse = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        {
            throw std::runtime_error("Error setting socket option SO_REUSEADDR: " + std::string(strerror(errno)));
        }
    }
    if (bind(server_sock, (struct sockaddr *)server_address, sizeof(*server_address)) < 0)
    {
        throw std::runtime_error("Error binding the datagram server socket: " + std::string(strerror(errno)));
    }

    return server_sock;
}

void print_usage(char *program_name)
{
    std::cerr << "Usage: " << program_name << " -e \"<command>\" [-(i|o|b) UDP/TCP(C<IP or HOSTNAME>,<PORT>|S<PORT>)]" << std::endl;
}

typedef struct
{
    struct sockaddr addr;
    int socktype;
    bool is_server;
} connection;

connection *parse_connection(char *arg)
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
        result->socktype = SOCK_STREAM;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    else if (strncmp(arg, "UDP", 3) == 0)
    {
        result->socktype = SOCK_DGRAM;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else if (strncmp(arg, "UDS", 3) == 0)
    {
        if (strlen(arg) < 5)
        {
            free(result);
            throw std::invalid_argument("UDS argument is too short");
        }
        if (arg[4] == 'S')
            result->socktype = SOCK_STREAM;
        else if (arg[4] == 'D')
            result->socktype = SOCK_DGRAM;
        else
        {
            free(result);
            throw std::invalid_argument("Unkown UDS type");
        }
        if (arg[3] == 'S')
            result->is_server = true;
        else if (arg[3] == 'C')
            result->is_server = false;
        else
        {
            free(result);
            throw std::invalid_argument("Unkown connection type specifier");
        }
        struct sockaddr_un *addr_unix = (struct sockaddr_un *)&result->addr;
        if (strlen(arg + 5) > sizeof(addr_unix->sun_path))
        {
            free(result);
            throw std::invalid_argument("UDS path is too long");
        }
        strcpy(addr_unix->sun_path, arg + 5);
        addr_unix->sun_family = AF_UNIX;
        return result;
    }
    else
    {
        free(result);
        throw std::invalid_argument("Unkown protocol specifier");
    }

    char *hostname = NULL, *port = (char *)malloc(MAX_PORT_SIZE);

    hints.ai_family = AF_INET;
    hints.ai_flags |= AI_ADDRCONFIG | AI_NUMERICSERV; // Returns IPv6 addresses only if your PC is compatible.

    if (arg[3] == 'S')
    {
        if (strlen(arg + 4) < 1)
        {
            free(port);
            throw std::invalid_argument("No port provided in server specifier");
        }
        strncpy(port, arg + 4, MAX_PORT_SIZE);

        try
        {
            if (std::stoi(port) < 0)
                throw std::exception();
        }
        catch (const std::exception &e)
        {
            free(port);
            throw std::invalid_argument("Invalid port number provided in server specifier");
        }

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

        try
        {
            std::stoi(port);
        }
        catch (const std::exception &e)
        {
            free(port);
            throw std::invalid_argument("Invalid port number provided in client specifier");
        }

        hostname = (char *)malloc(INET_ADDRSTRLEN);

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
        throw std::runtime_error("Error getting address info: " + std::string(gai_strerror(error)));
    }

    memcpy(&result->addr, addrinfo_ret->ai_addr, sizeof(result->addr));

    freeaddrinfo(addrinfo_ret); // Freeing the addrinfo struct
    free(port);
    free(hostname);

    return result;
}

int setup_connection(connection *conn)
{
    switch (conn->socktype)
    {
    case SOCK_STREAM:
        if (conn->is_server)
            return open_stream_server(&conn->addr);
        else
            return open_stream_client(&conn->addr);
    case SOCK_DGRAM:
        if (conn->is_server)
            return open_dgram_server(&conn->addr);
        else
            return open_dgram_client(&conn->addr);
    default:
        throw std::runtime_error("Invalid connection type");
    }
}

int piper(void *arg)
{
    int *fds = (int *)arg;
    int read_fd = fds[0], write_fd = fds[1];
    char buffer[PIPER_BUFFER_SIZE];
    while (true)
    {
        ssize_t n_read = read(read_fd, buffer, sizeof(buffer));
        if (n_read < 0)
        {
            return 1;
        }
        if (n_read == 0)
        {
            return 0;
        }
        ssize_t n_written = write(write_fd, buffer, n_read);
        if (n_written < 0)
        {
            return 1;
        }
        if (n_written == 0)
        {
            return 0;
        }
        if (n_written < n_read)
        {
            // TODO: write more?
        }
    }
    return 0;
}

void cleanup_all(int signum)
{
    (void)signum;

    for (auto &cu : to_cleanup)
    {
        cu->cleanup();
    }
    kill(0, SIGALRM);
}

int main(int argc, char *argv[])
{
    struct sigaction cleanup_action = {};
    cleanup_action.sa_handler = &cleanup_all;
    sigaction(SIGALRM, &cleanup_action, NULL);

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
            try
            {
                alarm(std::stoi(optarg));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error in timeout argument: Please enter a number" << std::endl;
                print_usage(argv[0]);
                return 1;
            }

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
                input = parse_connection(optarg);
                if (input->socktype == SOCK_DGRAM && !input->is_server)
                    throw std::invalid_argument("Cannot use datagram client as input");
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
                output = parse_connection(optarg);
                if (output->socktype == SOCK_DGRAM && output->is_server)
                    throw std::invalid_argument("Cannot use datagram server as output");
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
                both = parse_connection(optarg);
                if (both->socktype == SOCK_DGRAM)
                    throw std::invalid_argument("Cannot use datagram connection as both input and output");
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

        default:
            print_usage(argv[0]);
            std::cerr << "Unknown option: \'" << c << "\'" << std::endl;
            free(output);
            free(input);
            free(both);
            return 1;
        }
    }

    fflush(stdin);
    fflush(stdout);
    int input_fd = STDIN_FILENO, output_fd = STDOUT_FILENO;

    if (both != NULL)
    {
        try
        {
            input_fd = output_fd = setup_connection(both);
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
            input_fd = setup_connection(input);
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
            output_fd = setup_connection(output);
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

    free(output);
    free(input);
    free(both);

    if (command == NULL)
    {
        // run piper(input_fd, STDOUT_FILENO) & piper(STDIN_FILENO, output_fd)
        thrd_t input_piper;
        int input_fds[2] = {input_fd, STDOUT_FILENO};
        thrd_create(&input_piper, piper, input_fds);
        thrd_t output_piper;
        int output_fds[2] = {STDIN_FILENO, output_fd};
        thrd_create(&output_piper, piper, output_fds);
        int res;
        thrd_join(input_piper, &res);
        thrd_join(output_piper, &res);
    }
    else
    {
        if (dup2(input_fd, STDIN_FILENO) < 0)
        {
            perror("Error duping input file descriptor");
            return 1;
        }
        if (dup2(output_fd, STDOUT_FILENO) < 0)
        {
            perror("Error duping output file descriptor");
            return 1;
        }

        int wstatus;
        if (((wstatus = system(command)) != 0 && errno != 0) || WEXITSTATUS(wstatus) == 127)
        {
            perror("ERROR: On command execution (system(3))");
            std::cerr << "INFO: Command was \"" << command << "\"" << std::endl;
            return 1;
        }
    }

    for (auto &cu : to_cleanup)
    {
        cu->cleanup();
    }

    return 0;
}
