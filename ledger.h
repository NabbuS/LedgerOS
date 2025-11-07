#ifndef LEDGER_H
#define LEDGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define LOG_FILE "logs/ledger.log"
#define MONITORED_DIR "monitored/"

typedef struct {
    int event_id;
    char timestamp[64];
    char user[64];
    char action[256];
    char status[64];
    char prev_hash[65];
    char curr_hash[65];
} LedgerEntry;

void log_event(const char *user, const char *action, const char *status);
void generate_hash(const char *data, char *hash_out);
void get_current_time(char *buffer);
int get_last_event_id();
void raise_alert(const char *msg);
void verify_ledger();
void monitor_files();

#endif
