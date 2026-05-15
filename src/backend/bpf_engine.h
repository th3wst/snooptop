#pragma once

#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include "core/process_event.h"

struct snooptop_bpf;
struct ring_buffer;

class BpfEngine {
public:
    BpfEngine();
    ~BpfEngine();

    bool start();
    void stop();
    
    //used by the TUI to get a static snapshot for rendering
    std::vector<process_event_t> get_recent_events();
    
    //used by JSON mode to pop and clear events
    std::vector<process_event_t> consume_events();

private:
    static int handle_event(void *ctx, void *data, size_t data_sz);
    void poll_loop();

    snooptop_bpf* skel = nullptr;
    ring_buffer* ringbuf = nullptr;
    
    std::atomic<bool> running{false};
    std::thread poller_thread;

    std::mutex events_mutex;
    std::vector<process_event_t> recent_events;
};
