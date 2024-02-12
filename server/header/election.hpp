#ifndef ELECTION_HPP
#define ELECTION_HPP

#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <arpa/inet.h>
#include "server.hpp"


class Server {
public:
    Server(int id, const std::string& ip, bool alive = true) : id(id), ip(ip), alive(alive) {}

    // Métodos de acesso
    int getId() const { return id; }
    void setId(int newId) { id = newId; }

    const std::string& getIp() const { return ip; }
    void setIp(const std::string& newIp) { ip = newIp; }

    bool isAlive() const { return alive; }
    void setAlive(bool status) { alive = status; }

    // Métodos específicos
    void sendElectionMessage() const {
        // Implementação do envio de mensagem de eleição
        std::cout << "Sending election message to server " << id << std::endl;
    }

    void notifyElectionResult(bool elected) const {
        // Implementação da notificação de resultado de eleição
        std::cout << "Notifying server " << id << " about election result: " << (elected ? "elected" : "not elected") << std::endl;
    }

private:
    int id;
    std::string ip;
    bool alive;
};

class Election {
public:
    Election(int serverId);
    ~Election();
    
    void readServerListFromFile(const std::string& filename);
    void startElection();
    void notifyElectionResult(bool elected);

private:
    int serverId;
    std::vector<Server> servers;
};

#endif // ELECTION_HPP
