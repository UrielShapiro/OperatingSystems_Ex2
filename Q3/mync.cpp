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

void print_usage(char *program_name)
{
	std::cerr << "Usage: " << program_name << " -e \"<command>\" [-(i|o|b) TCP(C<IP or HOSTNAME>,<PORT>|S<PORT>)]" << std::endl;
}

struct sockaddr_in *parse_address(char *arg)
{
	if (strlen(arg) < 5)
	{
		throw std::invalid_argument("Argument is too short");
	}
	if (strncmp(arg, "TCP", 3) != 0)
	{
		throw std::invalid_argument("Unknown address specifier, only TCP is supported");
	}

	char *hostname = NULL, *port = (char *)malloc(MAX_PORT_SIZE);
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_family = AF_INET;		 // TODO: Consider supporting IPv6
	hints.ai_flags |= AI_ADDRCONFIG; // Returns IPv6 addresses only if your PC is compatible.

	if (arg[3] == 'S')
	{
		strncpy(port, arg + 4, MAX_PORT_SIZE);

		hints.ai_flags |= AI_PASSIVE;
	}
	else if (arg[3] == 'C')
	{
		char *comma = arg + 4;
		while (*comma != '\0' && *comma != ',')
			comma += 1;
		if (*comma == '\0') throw std::invalid_argument("No comma seperator in client specifier");
		strncpy(port, comma + 1, MAX_PORT_SIZE);

		hostname = (char *)malloc(INET_ADDRSTRLEN); // IPv6: max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)

		strncpy(hostname, arg + 4, comma - (arg + 4));
		hostname[comma - (arg + 4)] = '\0';
	}

	struct addrinfo *addrinfo_ret;
	int error = getaddrinfo(hostname, port, &hints, &addrinfo_ret);
	if (error != 0)
	{
		throw std::runtime_error(gai_strerror(error));
	}

	struct sockaddr_in *result = (sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memcpy(result, addrinfo_ret->ai_addr, sizeof(*result));

	freeaddrinfo(addrinfo_ret); // Freeing the addrinfo struct
	free(port);
	free(hostname);

	return result;
}

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cerr << "Not enough arguments provided" << std::endl;
		return 1;
	}

	struct sockaddr_in *input = NULL;
	struct sockaddr_in *output = NULL;
	struct sockaddr_in *both = NULL;

	char *command = NULL;
	char c;
	while ((c = getopt(argc, argv, "e:i:o:b:")) != -1)
	{
		switch (c)
		{
		case 'e':
			command = optarg;
			break;

		case 'i':
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
		if (both->sin_addr.s_addr == INADDR_ANY) // server
		{
			int server_sock = socket(both->sin_family, SOCK_STREAM, IPPROTO_TCP);
			if (server_sock < 0)
			{
				perror("Error opening a server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(server_sock);

			
			int reuse = 1;
			if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
			{
				perror("Error setting socket option SO_REUSEADDR");
				free(output);
				free(input);
				free(both);
				return 1;
			}

			if (bind(server_sock, (struct sockaddr *)both, sizeof(*both)) < 0)
			{
				perror("Error binding the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			if (listen(server_sock, 1) < 0)
			{
				perror("Error listening on server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			struct sockaddr client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			int sock = accept(server_sock, &client_addr, &client_addr_len);
			if (sock < 0)
			{
				perror("Error accepting client");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(sock);
			input_fd = output_fd = sock;
		}
		else
		{
			int sock = socket(both->sin_family, SOCK_STREAM, IPPROTO_TCP);
			if (sock < 0)
			{
				perror("Error opening a client socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(sock);
			
			if (connect(sock, (struct sockaddr *)both, sizeof(*both)) < 0)
			{
				perror("Error connecting to the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			input_fd = output_fd = sock;
		}
	}

	if (input != NULL)
	{
		if (input->sin_addr.s_addr == INADDR_ANY) // Server
		{
			int server_sock = socket(input->sin_family, SOCK_STREAM, IPPROTO_TCP);
			if (server_sock == -1)
			{
				perror("Error opening a server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}

			sockets.push_back(server_sock);

			int reuse = 1;
			if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
			{
				perror("Error setting socket option SO_REUSEADDR");
				free(output);
				free(input);
				free(both);
				return 1;
			}

			if (bind(server_sock, (struct sockaddr *)input, sizeof(*input)) < 0)
			{
				std::cerr << "Error binding the server socket" << std::endl;
				free(output);
				free(input);
				free(both);
				return 1;
			}

			if (listen(server_sock, 1) < 0)
			{
				perror("Error binding the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}

			struct sockaddr client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			int sock = accept(server_sock, &client_addr, &client_addr_len);
			if (sock < 0)
			{
				perror("Error accepting the client socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			input_fd = sock;
		}
		else
		{
			int sock = socket(input->sin_family, SOCK_STREAM, IPPROTO_TCP);
			if (sock < 0)
			{
				perror("Error creating a client socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(sock);
			
			if (connect(sock, (struct sockaddr *)input, sizeof(*input)) < 0)
			{
				perror("Error connecting to the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			input_fd = sock;
		}
	}

	if (output != NULL)
	{
		if (output->sin_addr.s_addr == INADDR_ANY) // Server
		{
			int server_sock = socket(output->sin_family, SOCK_STREAM, IPPROTO_TCP);

			if (server_sock == -1)
			{
				perror("Error opening a server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(server_sock);
			
			if (bind(server_sock, (struct sockaddr *)output, sizeof(*output)) < 0)
			{
				std::cerr << "Error binding the server socket" << std::endl;
				free(output);
				free(input);
				free(both);
				return 1;
			}
			if (listen(server_sock, 1) < 0)
			{
				perror("Error binding the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			struct sockaddr client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			int sock = accept(server_sock, &client_addr, &client_addr_len);
			if (sock < 0)
			{
				perror("Error accepting the client socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			output_fd = sock;
		}
		else
		{
			int sock = socket(output->sin_family, SOCK_STREAM, IPPROTO_TCP);
			if (sock < 0)
			{
				perror("Error creating a client socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			sockets.push_back(sock);

			if (connect(sock, (struct sockaddr *)output, sizeof(*output)) < 0)
			{
				perror("Error connecting to the server socket");
				free(output);
				free(input);
				free(both);
				return 1;
			}
			output_fd = sock;
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
		return 1;
	}

	for (int socket : sockets)
	{
		close(socket);
	}

	return 0;
}
