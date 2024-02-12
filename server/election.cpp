#include "header/election.hpp"

Election::Election(int serverId) : serverId(serverId) {}

Election::~Election() {}

void Election::readServerListFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening server list file!" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            std::istringstream iss(line);
            int id;
            std::string ip;
            char delimiter;
            iss >> id >> delimiter >> ip;
            bool isLocal = (id == serverId);
            servers.push_back(Server(id, ip, isLocal));
        }
    }
    file.close();
}

void Election::startElection() {
    std::cout << "Starting election process..." << std::endl;

    // Find servers with higher IDs
    std::vector<Server> higherServers;
    for (const Server& server : servers) {
        if (server.getId() > serverId && server.isAlive()) {
            higherServers.push_back(server);
        }
    }

    // If there are no servers with higher IDs, this server becomes leader
    if (higherServers.empty()) {
        std::cout << "This server is elected as leader!" << std::endl;
        // Assume here you have a function to start as leader
        // startAsLeader();
        return;
    }

    // Send election message to servers with higher IDs
    for (const Server& higherServer : higherServers) {
        std::cout << "Sending election message to server " << higherServer.getId() << std::endl;
        // Assume here you have a function in Server class to send election message
        // higherServer.sendElectionMessage();
    }

    // Wait for response from higher servers
    bool responseReceived = false;
    // Assume here you have a mechanism to wait for response
    // responseReceived = waitForResponse();

    if (!responseReceived) {
        // No response received, this server becomes leader
        std::cout << "No response received from higher servers. This server is elected as leader!" << std::endl;
        // Assume here you have a function to start as leader
        // startAsLeader();

        // Notify other servers about election result
        notifyElectionResult(true);
    }
}

void Election::notifyElectionResult(bool elected) {
    if (elected) {
        // Notify other servers about election result
        for (Server& server : servers) {
            if (server.getId() != serverId && server.isAlive()) {
                // Assume here you have a function in Server class to notify about election result
                // server.notifyElectionResult(true);
            }
        }
    }
}
