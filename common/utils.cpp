#include "header/utils.hpp"
#include <cstdlib>

std::string getCurrentDateTime() {
    time_t now = time(0);
    tm *ltm = localtime(&now);

    // Formata a data e hora como uma string
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", ltm);

    return buffer;
}

uint16_t getTimeStamp(){
    time_t now = time(0);
    return (uint16_t) now;
}

bool nameConsistency(std::string name){
    return (
        (name.length() >= 4 && name.length() <= 20) &&
        name.find(',') == std::string::npos &&
        name.find(';') == std::string::npos &&
        name.find(' ') == std::string::npos
    );
}

void clearScreen() {
    // Clear screen command based on platform
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}

void pressEnterToContinue() {
    std::cout << YELLOW << "\n[Press Enter to Continue]" << RESET;
    std::cin.ignore(); // Wait for Enter key press
}

std::vector<std::string> splitString(const std::string& input) {
    std::vector<std::string> result;
    std::istringstream iss(input);
    std::string token;
    
    while (std::getline(iss, token, ';')) {
        result.push_back(token);
    }
    
    return result;
}

//luis?kkkkkkk foi mal, discord enquanto espero minha janta fica pronta?
size_t hashIPPort(const std::string& id) {
    return std::hash<std::string>{}(id);
}