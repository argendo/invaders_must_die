#pragma once

#include <iostream>

#include "../detector/ISender.hpp"

class ConsoleSender : public Sender
{
public:
    virtual int send_alert(std::string &s_ip, std::string &d_ip, std::string &rule_name);
};