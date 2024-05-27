#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Not enough arguments provided" << std::endl;
        std::cerr << "Usage: ./mync -e \"<command>\"" << std::endl;
        return 1;
    }

    char *command = NULL;
    char c;
    while ((c = getopt(argc, argv, "e:")) != -1)
    {
        switch (c)
        {
        case 'e':
            command = optarg;
            break;

        default:
            std::cerr << "Usage: ./mync -e \"<command>\"" << std::endl;
            std::cerr << "Unknown option" << std::endl;
            break;
        }
    }

    if (command == NULL)
    {
        std::cerr << "Usage: ./mync -e \"<command>\"" << std::endl;
        std::cerr << "ERROR: Command not found" << std::endl;
        return 1;
    }

    fflush(STDIN_FILENO);
    if(system(command) < 0)
    {
        perror("ERROR: On command execution (system(3))");
        std::cerr << "INFO: Command was \"" << command << "\"" << std::endl;
    }
    
    return 0;
}
