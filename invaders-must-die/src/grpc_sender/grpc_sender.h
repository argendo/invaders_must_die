#pragma once

#include <iostream>
#include <memory>
#include <thread>

#include <grpc/support/log.h>
#include <grpcpp/grpcpp.h>

#include "alert.grpc.pb.h"

#include "../detector/ISender.hpp"

using alerts::Alert;
using alerts::Alert_RuleType;
using alerts::AlertCapturer;
using alerts::Result;

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;

class GrpcSender : public Sender
{
public:
    explicit GrpcSender(const std::shared_ptr<Channel> channel)
        : stub_(AlertCapturer::NewStub(channel)) {}

    virtual int send_alert(std::string s_ip, std::string d_ip, std::string rule_name);
    std::string id = "GrpcSender";
private:
    // Out of the passed in Channel comes the stub, stored here, our view of the
    // server's exposed services.
    std::unique_ptr<AlertCapturer::Stub> stub_;
};