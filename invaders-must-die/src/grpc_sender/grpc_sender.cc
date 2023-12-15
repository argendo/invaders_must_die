#pragma once

#include "includes.h"

int GrpcSender::send_alert(std::string s_ip, std::string d_ip, std::string rule_name)
{
    Alert alert;
    Result res;
    alert.set_d_ip(d_ip);
    alert.set_src_ip(s_ip);
    alert.set_rule_name(rule_name);
    alert.set_rule_type(Alert_RuleType::Alert_RuleType_RULE_ALERT);

    ClientContext ctx;
    CompletionQueue cq;
    Status status;

    std::unique_ptr<ClientAsyncResponseReader<Result>> rpc(
        stub_->AsyncSendAlert(&ctx, alert, &cq));

    rpc->Finish(&res, &status, (void *)1);
    void *got_tag;
    bool ok = false;
    // Block until the next result is available in the completion queue "cq".
    // The return value of Next should always be checked. This return value
    // tells us whether there is any kind of event or the cq_ is shutting down.
    GPR_ASSERT(cq.Next(&got_tag, &ok));

    // Verify that the result from "cq" corresponds, by its tag, our previous
    // request.
    GPR_ASSERT(got_tag == (void *)1);
    // ... and that the request was completed successfully. Note that "ok"
    // corresponds solely to the request for updates introduced by Finish().
    GPR_ASSERT(ok);

    // Act upon the status of the actual RPC.
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return 1;
    }
}