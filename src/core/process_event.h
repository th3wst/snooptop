#ifndef PROCESS_EVENT_H
#define PROCESS_EVENT_H

#define MAX_ARGS 10
#define ARGSIZE 64
#define TASK_COMM_LEN 16

struct process_event_t {
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned long long ts_ns;
    char comm[TASK_COMM_LEN];
    char args[MAX_ARGS][ARGSIZE];
};

#endif // PROCESS_EVENT_H
