#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <unistd.h>

#define LOG_TAG "AnogsBypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#include "dobby.h"

static const uintptr_t OFF_SECURITY_1   = 0x644CE28;
static const uintptr_t OFF_SECURITY_2   = 0x64738B8;
static const uintptr_t OFF_ANOGS_CASE16 = 0x2328F0;
static const uintptr_t OFF_SUB_6577204  = 0x6577204;

typedef void* (*security_func_t)(void* self, void* params);
typedef int64_t (*anogs_case16_t)(int64_t a1, const char* a2, bool a3);
typedef unsigned int* (*sub_6577204_t)(unsigned int* result, unsigned int a2);

static security_func_t orig_security_1 = nullptr;
static security_func_t orig_security_2 = nullptr;
static anogs_case16_t  orig_anogs_case16 = nullptr;
static sub_6577204_t   orig_sub_6577204 = nullptr;

static uintptr_t get_module_base(const char* name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            char* p = strtok(line, "-");
            if (p) { base = strtoul(p, nullptr, 16); break; }
        }
    }
    fclose(fp);
    return base;
}

static void* hooked_security_1(void* self, void* params) {
    LOGI("Security1 engellendi");
    return nullptr;
}

static void* hooked_security_2(void* self, void* params) {
    LOGI("Security2 engellendi");
    return nullptr;
}

static int64_t hooked_anogs_case16(int64_t a1, const char* a2, bool a3) {
    if (a2) {
        if (strstr(a2, "XTask_ob_x.zip") || strstr(a2, "MrpcsActiveSig")) {
            LOGI("Kritik string: %s", a2);
            while (true) sleep(500);
        }
    }
    if (orig_anogs_case16) return orig_anogs_case16(a1, a2, a3);
    return 0;
}

static unsigned int* hooked_sub_6577204(unsigned int* result, unsigned int a2) {
    LOGI("sub_6577204: a2=%u", a2);
    if (a2 <= 9) return result;
    if (orig_sub_6577204) return orig_sub_6577204(result, a2);
    return result;
}

__attribute__((constructor))
void on_load() {
    LOGI("AnogsBypass yuklendi");

    uintptr_t ue4 = get_module_base("libUE4.so");
    uintptr_t anogs = get_module_base("libanogs.so");
    LOGI("libUE4.so: 0x%lx", ue4);
    LOGI("libanogs.so: 0x%lx", anogs);

    if (ue4) {
        DobbyHook((void*)(ue4 + OFF_SECURITY_1), (void*)hooked_security_1, (void**)&orig_security_1);
        DobbyHook((void*)(ue4 + OFF_SECURITY_2), (void*)hooked_security_2, (void**)&orig_security_2);
        DobbyHook((void*)(ue4 + OFF_SUB_6577204), (void*)hooked_sub_6577204, (void**)&orig_sub_6577204);
    }
    if (anogs) {
        DobbyHook((void*)(anogs + OFF_ANOGS_CASE16), (void*)hooked_anogs_case16, (void**)&orig_anogs_case16);
    }
}
