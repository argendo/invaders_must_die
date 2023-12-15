#pragma once
#include <string>

class Sender {
    public:
        virtual int send_alert(std::string s_ip, std::string d_ip, std::string rule_name);
        int check = 1;
};