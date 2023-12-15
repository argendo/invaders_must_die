#pragma once

#include <yara.h>
#include <future>
#include <queue>

#include "ISender.hpp"
#include "DException.hpp"

enum D_ERROR
{
    D_ERROR_NO,
    D_ERROR_YES
};

struct tcp_payload
{
    std::string s_ip;
    std::string d_ip;
    const u_char *payload;
    size_t len;
};

class Detector
{
private:
    std::thread _t;             // Internal process thread
    std::queue<tcp_payload> _q; // Queue for payload;
    Sender* _s;                  // Sender for alerts
    YR_COMPILER *_yc;
    YR_SCANNER *_ys;
    YR_RULES *_rules;

    static void process_tcp_payload(std::queue<tcp_payload>* q, Sender* s, YR_RULES* rules);

    void init_yara_rules(FILE *rules_file);

public:
    Detector(Sender* sender, FILE *yara_rules_file);

    ~Detector();

    D_ERROR check_tcp_payload(const u_char *payload, size_t len, std::string s_ip, std::string d_ip);
};