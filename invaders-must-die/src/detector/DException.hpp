#pragma once

#include <iostream>
#include <string>

class DException : public std::exception
{
public:
    DException(const std::string &msg) : m_msg(msg){};

    virtual const char *what() const throw()
    {
        return m_msg.c_str();
    }

    const std::string m_msg;
};