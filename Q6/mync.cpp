#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <sys/un.h>
#include <threads.h>
#include <memory>
#include <signal.h>
#include <limits.h>

// the maximum length of a string representing a port
constexpr size_t MAX_PORT_SIZE = 6;
// the maximum length of a string representing a hostname or IP
constexpr size_t MAX_HOSTNAME_SIZE = std::max(INET_ADDRSTRLEN, HOST_NAME_MAX);
// used when there is no -e option, currently stored on stack so avoid sizes too large
constexpr size_t PIPER_BUFFER_SIZE = 1024;

// a class for something that needs to be cleaned up on exit
class Cleanup
{
public:
    // the clean up to be performed
    virtual void cleanup() = 0;
};

// a socket that needs to be closed
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

// a UDS bind that needs to be unlinked
class UDSCleanup : public Cleanup
{
    // memory is owned by this class
    char *filename;

public:
    UDSCleanup(char *file) : filename(strdup(file)) {}
    void cleanup() override
    {
        // unlink the socket
        unlink(filename);
        // free the owned memory
        free(filename);
        // prevent dangling pointer
        filename = NULL;
    }
};

// the vector of objects to be cleaned up
std::vector<std::unique_ptr<Cleanup>> to_cleanup;

int open_dgram_client(sockaddr *server_addr)
{
    int client_sock = socket(server_addr->sa_family, SOCK_DGRAM, 0);
    if (client_sock < 0)
    {
        throw std::runtime_error("Error opening a UDP client socket: " + std::string(strerror(errno)));
    }
    // add the socket to the cleanup
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(client_sock)));
    // find the proper length according to the family
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
    // add the socket to the cleanup
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(client_sock)));
    // find the proper length accrding to the family
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
    // add the server socket to the cleanup
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(server_sock)));

    if (server_address->sa_family == AF_UNIX)
    {
        // add the UDS socket to be unbinded
        to_cleanup.push_back(std::make_unique<UDSCleanup>(((sockaddr_un *)server_address)->sun_path));
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
    // add the client socket to the cleanup
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
    // add the server socket to the cleanup
    to_cleanup.push_back(std::make_unique<SockCleanup>(SockCleanup(server_sock)));

    if (server_address->sa_family == AF_UNIX)
    {
        // add the UDS socket to be unbinded
        to_cleanup.push_back(std::make_unique<UDSCleanup>(((sockaddr_un *)server_address)->sun_path));
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
    std::cerr << "Usage: " << program_name << " [-e \"<command>\"] [-(i|o|b) <connection specifier>]" << std::endl
              << "Use at most one specifier per direction, i.e. either -b alone or at most one of -i and -o each" << std::endl
              << "Valid connection specifiers:" << std::endl
              << "\tTCP: Use TCPS<port> for server or TCPC<hostname or IP>,<port> for client" << std::endl
              << "\tUDP: Use UDPS<port> for server or UDPC<hostname or IP>,<port> for client" << std::endl
              << "\tUnix Domain Socket: Use UDSS<socket type><socket path> for server or UDSC<socket type><socket path> for client" << std::endl
              << "\t\tValid socket types: \'S\' for stream socket, \'D\' for datagram socket" << std::endl;
}

enum HostType
{
    SERVER,
    CLIENT
};

// a struct representing a connection of the program
typedef struct
{
    // the sockaddr is a union to ensure enough space to store any possible value
    union
    {
        struct sockaddr addr;
        // the data must have enough space for either sockaddr_un or sockaddr_in
        uint8_t addr_data[std::max(sizeof(struct sockaddr_un), sizeof(struct sockaddr_in))];
    };
    // the socket_type, according to socket(2) parameter type
    int socktype;
    HostType host_type;
} connection;

// this function parses a connection specifier argument	into a connection struct
connection *parse_connection(char *arg)
{
    // connection specifier must have at least 4 characters (e.g. UDPC)
    if (strlen(arg) < 4)
    {
        throw std::invalid_argument("Argument is too short");
    }
    // initialize hints to be sent to getaddrinfo
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    // allocate result
    connection *result = (connection *)malloc(sizeof(connection));
    memset(result, 0, sizeof(*result));

    // check specifier type
    if (strncmp(arg, "TCP", 3) == 0)
    {
        // set result socktype
        result->socktype = SOCK_STREAM;
        // set hints
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    else if (strncmp(arg, "UDP", 3) == 0)
    {
        // set result socktype
        result->socktype = SOCK_DGRAM;
        // set hints
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else if (strncmp(arg, "UDS", 3) == 0)
    {
        // UDS specifier must have at least 5 characters (e.g. UDSCD)
        if (strlen(arg) < 5)
        {
            free(result);
            throw std::invalid_argument("UDS argument is too short");
        }
        // check socket type and set in result
        if (arg[4] == 'S')
            result->socktype = SOCK_STREAM;
        else if (arg[4] == 'D')
            result->socktype = SOCK_DGRAM;
        else
        {
            free(result);
            throw std::invalid_argument("Unkown UDS type");
        }
        // check host type and set in result
        if (arg[3] == 'S')
            result->host_type = SERVER;
        else if (arg[3] == 'C')
            result->host_type = CLIENT;
        else
        {
            free(result);
            throw std::invalid_argument("Unkown connection type specifier");
        }
        // make a pointer to the result address as a sockaddr_un
        struct sockaddr_un *addr_unix = (struct sockaddr_un *)&result->addr;
        // make sure the length of the string after the first 5 chars is not too large
        if (strlen(arg + 5) + 1 > sizeof(addr_unix->sun_path)) // + 1 for null terminator
        {
            free(result);
            throw std::invalid_argument("UDS path is too long");
        }
        // copy the path from arg + 5 to the sun_path
        strcpy(addr_unix->sun_path, arg + 5);
        // set the family
        addr_unix->sun_family = AF_UNIX;
        // we are done with UDS, we can return
        return result;
    }
    else
    {
        free(result);
        throw std::invalid_argument("Unkown protocol specifier");
    }
    // at this point we know the specifier is either TCP or UDP, the fields were set accordingly
    // we just need to parse the rest

    // initialize pointers to the hostname and the port (we make new memory for the port to copy into)
    char *hostname = NULL, *port = (char *)malloc(MAX_PORT_SIZE);

    // set hints
    hints.ai_family = AF_INET;        // TCP and UDP over IPv4
    hints.ai_flags |= AI_NUMERICSERV; // service will be numeric (port number)

    if (arg[3] == 'S') // a server specifier is of format (TCP|UDP)S<port>
    {
        // make sure there is some port
        if (strlen(arg + 4) < 1)
        {
            free(port);
            throw std::invalid_argument("No port provided in server specifier");
        }
        // copy it into the port string
        strncpy(port, arg + 4, MAX_PORT_SIZE);

        // make sure it is numeric, try to parse into a number and make sure it is not negative
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

        hints.ai_flags |= AI_PASSIVE; // to get server address from getaddrinfo

        // set type to server
        result->host_type = SERVER;
    }
    else if (arg[3] == 'C') // a client specifier is of format (TCP|UDP)C<hostname or IP>,<port>
    {
        // pointer to the comma (that should exist)
        char *comma = arg + 4;
        // find the comma
        while (*comma != '\0' && *comma != ',')
            comma += 1;
        // if reached null, there was no comma
        if (*comma == '\0')
        {
            free(port);
            throw std::invalid_argument("No comma seperator in client specifier");
        }
        // make sure there is something after the comma
        if (strlen(comma + 1) < 1)
        {
            free(port);
            throw std::invalid_argument("No port provided in client specifier");
        }
        // copy the port (1 char after the comma until the end) into the buffer
        strncpy(port, comma + 1, MAX_PORT_SIZE);

        // make sure it is numeric, try to parse into a number and make sure it is not negative
        try
        {
            std::stoi(port);
        }
        catch (const std::exception &e)
        {
            free(port);
            throw std::invalid_argument("Invalid port number provided in client specifier");
        }

        // if the comma is the 5th char, there is no IP or hostname
        if (comma == arg + 4)
        {
            free(port);
            throw std::invalid_argument("No IP or hostname provided in client specifier");
        }
        // if the difference is too large, the hostname provided is too long
        if ((size_t)(comma - (arg + 4)) > MAX_HOSTNAME_SIZE)
        {
            free(port);
            throw std::invalid_argument("Hostname or IP is too long");
        }

        // allocate memory for the hostname
        hostname = (char *)malloc(MAX_HOSTNAME_SIZE + 1); // + 1 for null terminator

        // copy the hostname into the buffer, should be (comma - (arg + 4)) chars
        strncpy(hostname, arg + 4, comma - (arg + 4));
        // put null terminator in hostname buffer
        hostname[comma - (arg + 4)] = '\0';

        // set as client
        result->host_type = CLIENT;
    }
    else
    {
        throw std::invalid_argument("Unkown connection type specifier");
    }

    // initialize return of getaddrinfo
    struct addrinfo *addrinfo_ret;
    // call it with the accumulated hints, hostname, and port, save result into addrinfo_ret
    int error = getaddrinfo(hostname, port, &hints, &addrinfo_ret);
    // check for errors
    if (error != 0)
    {
        free(port);
        free(hostname);
        throw std::runtime_error("Error getting address info: " + std::string(gai_strerror(error))); // gai = getaddrinfo
    }

    // copy the return (in ai_addr) into the addr_data of the result (which means result->addr is now a valid sockaddr_in)
    memcpy(&result->addr_data, addrinfo_ret->ai_addr, sizeof(result->addr_data));

    // free the returned struct
    freeaddrinfo(addrinfo_ret);
    free(port);
    free(hostname);

    // return the result
    return result;
}

// factory method to set up a connection, takes a pointer to a connection struct and returns a file descriptor over which the communication can occur
int setup_connection(connection *conn)
{
    switch (conn->socktype)
    {
    case SOCK_STREAM:
        if (conn->host_type == SERVER)
            return open_stream_server(&conn->addr);
        else
            return open_stream_client(&conn->addr);
    case SOCK_DGRAM:
        if (conn->host_type == SERVER)
            return open_dgram_server(&conn->addr);
        else
            return open_dgram_client(&conn->addr);
    default:
        throw std::runtime_error("Invalid connection type");
    }
}

// conforms to thrd_start_t to run multithreaded
// this functions takes a int[2] = {read_fd, write_fd} and pipes information from read_fd to write_fd until either closes
int piper(void *arg)
{
    // extract two fds from the argument
    int *fds = (int *)arg;
    int read_fd = fds[0], write_fd = fds[1];
    // create a buffer for communicated data
    char buffer[PIPER_BUFFER_SIZE];
    while (true)
    {
        // read data into the buffer
        ssize_t n_read = read(read_fd, buffer, sizeof(buffer));
        // check for error
        if (n_read < 0)
        {
            return 1;
        }
        // check for close
        if (n_read == 0)
        {
            return 0;
        }
        // write the data
        ssize_t n_written = write(write_fd, buffer, n_read);
        // check for error
        if (n_written < 0)
        {
            return 1;
        }
        // check for close
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

// cleans up all accumulated Cleanups from to_cleanup, should be performed on SIGALRM
void cleanup_all(int signum)
{
    (void)signum; // don't care which signal, should only be SIGALRM anyway

    // go through the pointers
    for (auto &cu : to_cleanup)
    {
        // clean up each one
        cu->cleanup();
    }
    kill(0, SIGALRM); // kill all living children
    exit(0);
}

int main(int argc, char *argv[])
{
    // set the action of SIGALRM to be cleanup_all
    {
        struct sigaction cleanup_action = {};
        cleanup_action.sa_handler = &cleanup_all;
        sigaction(SIGALRM, &cleanup_action, NULL);
    }

    // pointers to the connections
    connection *input = NULL;
    connection *output = NULL;
    connection *both = NULL;

    // the command to run (if -e is provided)
    char *command = NULL;
    char c;
    // get an option
    while ((c = getopt(argc, argv, "e:i:o:b:t:")) != -1)
    {
        switch (c)
        {
        case 't':
            // -t option, set an alarm and make sure it is numeric
            try
            {
                // parse the timeout
                long timeout = std::stol(optarg);
                // make sure it is positive
                if (timeout <= 0)
                    throw std::invalid_argument("Can't have non-positive timeout");
                // set an alarm
                alarm(timeout);
            }
            catch (const std::exception &e)
            {
                // on error, either print the explanation or a custom explanation for stol
                std::cerr << "Error in timeout argument: " << (strcmp(e.what(), "stol") == 0 ? "Please enter a number" : e.what()) << std::endl;
                print_usage(argv[0]);
                return 1;
            }
            break;

        case 'e':
            // -e option, copy the string into command
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
                // parse the specifier
                input = parse_connection(optarg);
                // datagram limitations
                if (input->socktype == SOCK_DGRAM && input->host_type == CLIENT)
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
            // runtime errors occur by getaddrinfo
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
                if (output->socktype == SOCK_DGRAM && output->host_type == SERVER)
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
                return 1;
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

        case '?':
            print_usage(argv[0]);
            free(output);
            free(input);
            free(both);
            return 1;
        default:
            abort();
        }
    }

    // flush files before duping them
    fflush(stdin);
    fflush(stdout);
    // default fds as standard files
    int input_fd = STDIN_FILENO, output_fd = STDOUT_FILENO;

    // check if we set a connection for both
    if (both != NULL)
    {
        try
        {
            // set up the connection and use the fd as both
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
            // set up the connection and use fd as input
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
            // set up the connection and use fd as output
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

    // free memory allocated by setup_connection or its callees
    free(output);
    free(input);
    free(both);

    // no -e option, need to pipe input to stdout and stdin to output
    if (command == NULL)
    {
        // run piper(input_fd, STDOUT_FILENO) & piper(STDIN_FILENO, output_fd)
        // piper expects int[2]
        thrd_t input_piper;
        // create an array with the fds
        int input_fds[2] = {input_fd, STDOUT_FILENO};
        // run the piper
        thrd_create(&input_piper, piper, input_fds);
        thrd_t output_piper;
        int output_fds[2] = {STDIN_FILENO, output_fd};
        thrd_create(&output_piper, piper, output_fds);
        int res;
        // join the 2 pipers, they will finish when the connection closes
        thrd_join(input_piper, &res);
        thrd_join(output_piper, &res);
    }
    else
    {
        // we need to run command with stdin and stdout going to input_fd and output_fd
        // so we dup each one to the proper fd
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

        // run the command, error happens if it returned non-zero and set errno
        int wstatus;
        if ((wstatus = system(command)) != 0 && errno != 0)
        {
            perror("ERROR: On command execution (system(3))");
            std::cerr << "INFO: Command was \"" << command << "\"" << std::endl;
            return 1;
        }
        // if the shell exit status is 127 the executable was not found
        if (WEXITSTATUS(wstatus) == 127)
        {
            std::cerr << "ERROR: Executable not found" << std::endl;
            std::cerr << "INFO: Command was \"" << command << "\"" << std::endl;
            return 1;
        }
    }

    // clean up all resources
    for (auto &cu : to_cleanup)
    {
        cu->cleanup();
    }

    return 0;
}
