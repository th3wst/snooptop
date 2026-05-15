#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include "backend/bpf_engine.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/loop.hpp>

using namespace ftxui;

std::string format_args(const process_event_t& e) {
    std::string cmd;
    for (int i = 0; i < MAX_ARGS; i++) {
        if (e.args[i][0] == '\0') break;
        cmd += std::string(e.args[i]) + " ";
    }
    if (!cmd.empty()) cmd.pop_back();
    return cmd;
}

//simple manual JSON formatter
std::string format_json(const process_event_t& e) {
    return "{\"ts_ns\":" + std::to_string(e.ts_ns) +
           ",\"pid\":" + std::to_string(e.pid) +
           ",\"ppid\":" + std::to_string(e.ppid) +
           ",\"uid\":" + std::to_string(e.uid) +
           ",\"comm\":\"" + std::string(e.comm) + "\"" +
           ",\"cmdline\":\"" + format_args(e) + "\"}";
}

int main(int argc, char* argv[]) {
    bool json_mode = false;

    //argument Parsing
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            std::cout << "snooptop v1.0.0 : Modern Linux executable tracing utility\n\n"
                      << "Usage: snooptop [OPTIONS]\n"
                      << "Options:\n"
                      << "  -h, --help    Show this help message and exit\n"
                      << "  -j, --json    Bypass the TUI and stream events as JSON lines\n\n"
                      << "Note: eBPF tracing requires root privileges.\n";
            return 0;
        } else if (std::strcmp(argv[i], "--json") == 0 || std::strcmp(argv[i], "-j") == 0) {
            json_mode = true;
        } else {
            std::cerr << "Unknown argument: " << argv[i] << "\nUse --help for usage.\n";
            return 1;
        }
    }

    BpfEngine engine;
    
    if (!engine.start()) {
        std::cerr << "Failed to start eBPF engine. Are you running with sudo?\n";
        return 1;
    }

    //JSON streaming Mode
    if (json_mode) {
        while (true) {
            auto events = engine.consume_events();
            for (const auto& e : events) {
                std::cout << format_json(e) << "\n";
            }
            if (!events.empty()) {
                std::cout.flush(); //esure piping to jq works smoothly
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    auto screen = ScreenInteractive::Fullscreen();
    
    auto renderer = Renderer([&] {
        auto events = engine.get_recent_events();
        
        Elements process_lines;
        
        //header
        process_lines.push_back(
            hbox({
                text(" PID   ") | bold,
                text(" PPID  ") | bold,
                text(" COMM            ") | bold,
                text(" CMDLINE ") | bold
            })
        );

        process_lines.push_back(separator());

        //process rendering with distinct color coding
        for (auto it = events.rbegin(); it != events.rend(); ++it) {
            process_lines.push_back(
                hbox({
                    text(std::to_string(it->pid)) | size(WIDTH, EQUAL, 7) | color(Color::Green),
                    text(std::to_string(it->ppid)) | size(WIDTH, EQUAL, 7) | color(Color::Yellow),
                    text(std::string(it->comm)) | size(WIDTH, EQUAL, 16) | color(Color::Cyan),
                    text(format_args(*it)) | color(Color::White)
                })
            );
        }

        return window(text(" snooptop v1.0.0 (Press 'q' to quit) ") | bold | center,
            vbox(std::move(process_lines))
        );
    });

    auto component = CatchEvent(renderer, [&](Event event) {
        if (event == Event::Character('q') || event == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });

    Loop loop(&screen, component);
    while (!loop.HasQuitted()) {
        loop.RunOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        screen.PostEvent(Event::Custom); 
    }

    engine.stop();
    return 0;
}
