//#include "header/data.hpp"
#include <string>
#include <sstream>
#include <cassert>
#include <iostream>
#include <vector>
#include <set>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <arpa/inet.h>
#include <ifaddrs.h>

sockaddr_in stringToSockaddr_in(const std::string& str) {
    sockaddr_in addr;
    size_t pos = str.find(':');
    std::string ip = str.substr(0, pos);
    int port = std::stoi(str.substr(pos + 1));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    return addr;
}

std::unordered_map<int, std::vector<sockaddr_in>> split(std::string input){
    std::string token;
    std::istringstream iss(input);
    std::unordered_map<int, std::vector<sockaddr_in>> connectedUsers;

    while (std::getline(iss, token, ';')) {
        std::istringstream userStream(token);
        std::string userToken;

        std::cout << "Token: " << token << std::endl;

        if (std::getline(userStream, userToken, '=')) {
            std::istringstream sessionStream(userToken);
            
            std::cout << "userToken: " << userToken << std::endl;

            int userId = std::stoi(userToken);
            std::vector<sockaddr_in> connectedSessions;

            while (std::getline(userStream, userToken, ',')) {
                std::cout << "userTokenInside: " << userToken << std::endl;
                sockaddr_in addr = stringToSockaddr_in(userToken);
                std::string ip = inet_ntoa(addr.sin_addr);
                int port = ntohs(addr.sin_port);
                std::cout << "IP: " << ip << std::endl;
                std::cout << "Port: " << port << std::endl;
                connectedSessions.push_back(addr);
            }

            connectedUsers[userId] = connectedSessions;
        }
    }
    return connectedUsers;
}

int main(){
    std::string str = "0=0.0.0.0:0000,0.0.0.1:0000;1=0.0.0.0:0000,0.0.0.1:0000";

    std::unordered_map<int, std::vector<sockaddr_in>> connectedUsers = split(str);
}
/*
int main1() {
    // Test serializeFollowPayload and deserializeFollowPayload
    std::string serializedFollowPayload = serializeFollowPayload(456, "john_doe");
    std::pair<int, std::string> deserializedFollowPayload = deserializeFollowPayload(serializedFollowPayload);
    assert(deserializedFollowPayload.first == 456);
    assert(deserializedFollowPayload.second == "john_doe");

    // Test serializeExitPayload and deserializeExitPayload
    std::string serializedExitPayload = serializeExitPayload(789);
    int deserializedExitPayload = deserializeExitPayload(serializedExitPayload);
    assert(deserializedExitPayload == 789);

    // Test serializeLoginPayload and deserializeLoginPayload
    std::string serializedLoginPayload = serializeLoginPayload("user123");
    std::string deserializedLoginPayload = deserializeLoginPayload(serializedLoginPayload);
    assert(deserializedLoginPayload == "user123");

    // Test serializePingPayload and deserializePingPayload
    std::string serializedPingPayload = serializePingPayload(999);
    int deserializedPingPayload = deserializePingPayload(serializedPingPayload);
    assert(deserializedPingPayload == 999);

    // Test serializePacket and deserializePacket
    Packet packet;
    packet.type = 1;
    packet.sequence_number = 42;
    packet.timestamp = 12345;
    std::strcpy(packet.payload, "Hello, Packet!");
    std::string serializedPacket = serializePacket(packet);
    Packet deserializedPacket = deserializePacket(serializedPacket);
    assert(deserializedPacket.type == 1);
    assert(deserializedPacket.sequence_number == 42);
    assert(deserializedPacket.timestamp == 12345);
    assert(std::strcmp(deserializedPacket.payload, "Hello, Packet!") == 0);

    std::cout << "All tests passed successfully!" << std::endl;

    return 0;
}*/