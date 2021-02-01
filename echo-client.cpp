#include "connection.h"
#include "client.h"
#include "log.h"


struct uv_destroyer {
    void operator()(uv_loop_t* ptr) {
        uv_loop_close(ptr);
        free(ptr);
    }
};

int main() {
    std::unique_ptr<uv_loop_t, uv_destroyer> loop_ptr{new uv_loop_t};
    auto* loop = loop_ptr.get();
    uv_loop_init(loop);

    quic::Debug("Initializing client");
    quic::Client s{{{127,0,0,1}, 4242}, loop};
    quic::Debug("Initialized client");

    uv_run(loop, UV_RUN_DEFAULT);

    return 0;
}
