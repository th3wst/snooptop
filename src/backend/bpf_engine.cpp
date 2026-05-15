#include "bpf_engine.h"
#include <bpf/libbpf.h>
#include <iostream>
#include "snooptop.skel.h"

BpfEngine::BpfEngine() {}

BpfEngine::~BpfEngine() {
    stop();
}

int BpfEngine::handle_event(void *ctx, void *data, size_t data_sz) {
    auto* engine = static_cast<BpfEngine*>(ctx);
    auto* e = static_cast<process_event_t*>(data);

    std::lock_guard<std::mutex> lock(engine->events_mutex);
    engine->recent_events.push_back(*e);
    
    //evict old entries so memory doesn't grow infinitely
    if (engine->recent_events.size() > 1000) {
        engine->recent_events.erase(engine->recent_events.begin());
    }
    return 0;
}

bool BpfEngine::start() {
    //open the skeleton
    skel = snooptop_bpf__open();
    if (!skel) return false;

    //load it into the kernel
    if (snooptop_bpf__load(skel)) {
        snooptop_bpf__destroy(skel);
        return false;
    }

    //attach the tracepoints
    if (snooptop_bpf__attach(skel)) {
        snooptop_bpf__destroy(skel);
        return false;
    }

    //setup ring buffer polling
    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, this, nullptr);
    if (!ringbuf) return false;

    running = true;
    poller_thread = std::thread(&BpfEngine::poll_loop, this);
    
    return true;
}

void BpfEngine::stop() {
    running = false;
    if (poller_thread.joinable()) {
        poller_thread.join();
    }
    if (ringbuf) {
        ring_buffer__free(ringbuf);
        ringbuf = nullptr;
    }
    if (skel) {
        snooptop_bpf__destroy(skel);
        skel = nullptr;
    }
}

void BpfEngine::poll_loop() {
    while (running) {
        ring_buffer__poll(ringbuf, 100);
    }
}

std::vector<process_event_t> BpfEngine::get_recent_events() {
    std::lock_guard<std::mutex> lock(events_mutex);
    return recent_events; 
}

std::vector<process_event_t> BpfEngine::consume_events() {
    std::lock_guard<std::mutex> lock(events_mutex);
    //move the data out and clear the internal vector
    std::vector<process_event_t> events = std::move(recent_events);
    recent_events.clear();
    return events;
}
