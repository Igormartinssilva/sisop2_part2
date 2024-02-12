#include "header/election.hpp"

Election::Election(int serverId) : serverId(serverId) {}

Election::Election() {}

Election::~Election() {}

void Election::readServerListFromFile() {
   
    std::string filename = "server_list.txt";
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "Error opening server list file!" << std::endl;
        return;
    }

    std::string line;
    int id;
    int port;
    std::string ip;
    bool isLocal;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            std::istringstream iss(line);
            std::string token;
            std::vector<std::string> tokens;
           
            while (iss >> token) {
                tokens.push_back(token);
            }

            if (tokens.size() == 4 && tokens[0] == "*") {
                id = std::stoi(tokens[1]);
                ip = tokens[2];
                port = tokens[3];
                isLocal = true;
            }
            else if (tokens.size() == 3 ) {
                id = std::stoi(tokens[0]);
                ip = tokens[1];
                port = tokens[2];
                isLocal = false;
            }
                servers.push_back(Server(id, ip, isLocal));
           
        }
    }
    file.close();
}


std::vector<std::pair<int, std::string>> Election::startElection() {
    std::cout << "Starting election process..." << std::endl;

    // Find servers with higher IDs and their IPs
    std::vector<std::pair<int, std::string>> higherServers; // Armazenando ID e IP dos servidores com IDs maiores
    for (const Server& server : servers) {
        if (server.getId() > serverId && server.isAlive()) {
            higherServers.push_back({server.getId(), server.getIp()}); // Adicionando ID e IP à lista
        }
    }

    // If there are no servers with higher IDs, this server becomes leader
    return higherServers;
    /*
    if (higherServers.empty()) {
        std::cout << "This server is elected as leader!" << std::endl;
        // Assume here you have a function to start as leader
        // notifyElectionResult(true);
        // startAsLeader();

        return higherServers;
    }

     // Send election message to servers with higher IDs
    for (const auto& server : higherServers) {
        int id = server.first;
        std::string ip = server.second;
        std::cout << "Sending election message to server " << id << " with IP " << ip << std::endl;
        // Assume aqui que você tem um método na classe Server para enviar a mensagem de eleição
        // server.sendElectionMessage(ip); // Supondo que o método de envio de mensagem requer o IP do destinatário
    }

    // Wait for response from higher servers
    bool responseReceived = false;
    // Assume here you have a mechanism to wait for response
    //ping
    // responseReceived = waitForResponse();

    if (!responseReceived) {
        // No response received, this server becomes leader
        std::cout << "No response received from higher servers. This server is elected as leader!" << std::endl;
        // Assume here you have a function to start as leader
        // startAsLeader();

        // Notify other servers about election result
        notifyElectionResult(true);
    }
    */
}

void Election::notifyElectionResult(bool elected) {
    if (elected) {
        // Notify other servers about election result
        for (Server& server : servers) {
            if (server.getId() != serverId && server.isAlive()) {
                // Assume here you have a function in Server class to notify about election result
                // server.notifyElectionResult(true);
                //Para fazer a função isAlive, podemos usar um ping de a cada 1 segundo para os outros servidores
                
                // envia mensagem aos servidores ativos informando quem é o novo lider
                // cada servidor vai receber uma msg ("elec") (id_lider, ip_lider)
                // caso id_lider == id_local, então atualiza a variavel isMainServer
                // caso contrario atualiza o endereço para o main server atual
            }
        }
    }
}
