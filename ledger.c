#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>

#define MONITOR_DIR "monitored"
#define LOG_FILE "ledger_log.txt"


void sha256_string(const char *str, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)str, strlen(str), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);
    output[64] = '\0';
}


void get_time(char *buf) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);
}


void get_last_hash(char *last_hash) {
    FILE *f = fopen(LOG_FILE, "r");
    if (!f) {
        strcpy(last_hash, "GENESIS");
        return;
    }
    char line[256], temp[65] = "GENESIS";
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "Curr_Hash: %64s", temp) == 1)
            strcpy(last_hash, temp);
    fclose(f);
}


void log_event(const char *event, const char *file) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    char ts[26], prev_hash[65], curr_hash[65], data[512];
    get_time(ts);
    get_last_hash(prev_hash);

    snprintf(data, sizeof(data), "%s|%s|%s|%s", ts, event, file, prev_hash);
    sha256_string(data, curr_hash);

    fprintf(f,
        "Timestamp: %s\n"
        "Event: %s\n"
        "File: %s\n"
        "Prev_Hash: %s\n"
        "Curr_Hash: %s\n\n",
        ts, event, file, prev_hash, curr_hash);
    fclose(f);

    printf("\n\033[1;36m=============================\033[0m\n");
    printf("Timestamp : %s\n", ts);
    printf("File      : %s\n", file);
    printf("Event     : %s\n", event);
    printf("Prev Hash : %s\n", prev_hash);
    printf("Curr Hash : %s\n", curr_hash);
    printf("\033[1;36m=============================\033[0m\n");
}

int verify_ledger() {
    FILE *f = fopen(LOG_FILE, "r");
    if (!f) {
        printf("No existing ledger. Starting fresh.\n");
        return 1;
    }

    char line[256], prev_hash[65] = "GENESIS", curr_hash[65], timestamp[64], event[64], file[128];
    int ok = 1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Timestamp: %63[^\n]", timestamp)) continue;
        if (sscanf(line, "Event: %63[^\n]", event)) continue;
        if (sscanf(line, "File: %127[^\n]", file)) continue;
        if (sscanf(line, "Prev_Hash: %64s", prev_hash)) continue;
        if (sscanf(line, "Curr_Hash: %64s", curr_hash)) {
    
            char test_hash[65], buffer[512];
            snprintf(buffer, sizeof(buffer), "%s|%s|%s|%s", timestamp, event, file, prev_hash);
            sha256_string(buffer, test_hash);
            if (strcmp(test_hash, curr_hash) != 0) {
                ok = 0;
                printf("\n Tampering detected near event: %s (%s)\n", event, file);
                break;
            }
        }
    }
    fclose(f);

    if (ok)
        printf("\nLedger Robust — no tampering detected.\n");
    else
        printf("\nLedger integrity compromised!\n");
    return ok;
}


int main(void) {
    printf("\nSECURE LEDGEROS + HASHCHAIN MONITOR\n");
    printf("Monitoring folder: %s\n", MONITOR_DIR);
    printf("-------------------------------------------\n");

    verify_ledger();

    HANDLE dir = CreateFileA(
        MONITOR_DIR,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (dir == INVALID_HANDLE_VALUE) {
        printf("Folder not found. Please create '%s' first.\n", MONITOR_DIR);
        return 1;
    }

    log_event("System started monitoring", MONITOR_DIR);

    char buffer[1024];
    DWORD bytesReturned;

    while (1) {
        if (ReadDirectoryChangesW(
                dir, buffer, sizeof(buffer), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_CREATION,
                &bytesReturned, NULL, NULL)) {

            FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)buffer;
            do {
                char fileName[256];
                int len = WideCharToMultiByte(CP_UTF8, 0,
                    info->FileName, info->FileNameLength / sizeof(WCHAR),
                    fileName, sizeof(fileName) - 1, NULL, NULL);
                fileName[len] = '\0';

                switch (info->Action) {
                    case FILE_ACTION_ADDED:
                        log_event(" New file created", fileName);
                        break;
                    case FILE_ACTION_REMOVED:
                        log_event("File deleted", fileName);
                        break;
                    case FILE_ACTION_MODIFIED:
                        log_event("File modified", fileName);
                        break;
                    case FILE_ACTION_RENAMED_OLD_NAME:
                        log_event("File renamed (old name)", fileName);
                        break;
                    case FILE_ACTION_RENAMED_NEW_NAME:
                        log_event("File renamed (new name)", fileName);
                        break;
                    default:
                        log_event("Unknown change", fileName);
                }

                if (info->NextEntryOffset == 0)
                    break;
                info = (FILE_NOTIFY_INFORMATION *)((BYTE *)info + info->NextEntryOffset);
            } while (1);
        }
    }

    CloseHandle(dir);
    return 0;
}
