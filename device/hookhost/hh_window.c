/* hh_window.c - FS-side client for the xci sysmodule's shared page window.
 *
 * sm parks GetService until "xci" is registered, and the sysmodule cannot
 * register before FS has served its file opens. The lookup, the IPC and the
 * mapping therefore run on a private thread that FS never waits for.
 */
#include "hh.h"
#include "hh_window.h"
#include "hh_swap.h"

#include <switch.h>

/* nnSdk keeps the current thread's handle in this TLS slot and uses it as the
 * owner tag of its internal locks (FS 23.5.0 sub_1A9AD0 / sub_1A9B60). */
#define HH_TLS_SDK_HANDLE 0x110
/* Mapping and card insertion wait this long after the sysmodule answers, so
 * that the system reaches HOME exactly as it does without a card. Ordering
 * only; svcMapSharedMemory is the one SVC here that FS itself never issues. */
#define HH_SETTLE_NS (15ull * 1000 * 1000 * 1000)
#define HH_LOOKUP_TRIES 30
#define HH_LOOKUP_RETRY_NS (1000ull * 1000 * 1000)
/* The heap and alias regions are placed at random and reject shared mappings,
 * so step down from HH_WINDOW_VA until one address is accepted. */
#define HH_WINDOW_VA_STEP 0x800000000ULL
#define HH_WINDOW_VA_TRIES 8
#define HH_POLL_NS (HH_SWAP_POLL_MS * 1000000ull)

static void (*g_on_ready)(hh_window_t *);
static void (*g_on_poll)(hh_window_t *);
static Handle g_thread;
static bool g_started;
static uint8_t g_stack[0x2000] __attribute__((aligned(16)));

/* Ask the sysmodule for its shared memory handle. Blocks in sm until "xci"
 * is registered. */
static Handle window_handle(void)
{
    if (R_FAILED(smInitialize()))
        return INVALID_HANDLE;

    Handle session;
    if (R_FAILED(smGetServiceOriginal(&session, smEncodeName("xci"))))
        return INVALID_HANDLE;

    Service xci;
    serviceCreate(&xci, session);

    Handle handles[8] = {0};
    SfDispatchParams p = {0};
    p.out_handle_attrs.attr0 = SfOutHandleAttr_HipcCopy;
    p.out_handles = handles;
    Result rc = serviceDispatchImpl(&xci, 0, NULL, 0, NULL, 0, p);
    serviceClose(&xci);

    return R_SUCCEEDED(rc) ? handles[0] : INVALID_HANDLE;
}

static hh_window_t *window_map(Handle shmem)
{
    hh_window_t *w = NULL;
    for (int i = 0; i < HH_WINDOW_VA_TRIES && w == NULL; i++) {
        void *va = (void *)(HH_WINDOW_VA - i * HH_WINDOW_VA_STEP);
        if (R_SUCCEEDED(svcMapSharedMemory(shmem, va, HH_WINDOW_SIZE, Perm_Rw)))
            w = (hh_window_t *)va;
    }
    svcCloseHandle(shmem);
    return w;
}

static void window_thread(void *arg)
{
    (void)arg;
    *(Handle *)((uint8_t *)armGetTls() + HH_TLS_SDK_HANDLE) = g_thread;

    Handle shmem = INVALID_HANDLE;
    for (int i = 0; i < HH_LOOKUP_TRIES && shmem == INVALID_HANDLE; i++) {
        if (i > 0)
            svcSleepThread(HH_LOOKUP_RETRY_NS);
        shmem = window_handle();
    }
    if (shmem != INVALID_HANDLE) {
        svcSleepThread(HH_SETTLE_NS);
        hh_window_t *w = window_map(shmem);
        if (w != NULL) {
            g_on_ready(w);
            /* Serves image swaps for the rest of FS's life. */
            for (;;) {
                svcSleepThread(HH_POLL_NS);
                g_on_poll(w);
            }
        }
    }
    svcExitThread();
}

uint32_t hh_now_ms(void)
{
    return (uint32_t)(armTicksToNs(armGetSystemTick()) / 1000000u);
}

void hh_window_start(void (*ready)(hh_window_t *), void (*poll)(hh_window_t *))
{
    if (__atomic_exchange_n(&g_started, true, __ATOMIC_ACQ_REL))
        return;
    g_on_ready = ready;
    g_on_poll = poll;
    /* The caller's priority is one the kernel is known to allow for FS. */
    s32 prio;
    if (R_SUCCEEDED(svcGetThreadPriority(&prio, CUR_THREAD_HANDLE)) &&
        R_SUCCEEDED(svcCreateThread(&g_thread, window_thread, NULL,
                                    g_stack + sizeof(g_stack), prio, -2))) {
        if (R_SUCCEEDED(svcStartThread(g_thread)))
            return;
        svcCloseHandle(g_thread);
    }
    __atomic_store_n(&g_started, false, __ATOMIC_RELEASE);
}

void hh_window_pause(void)
{
    svcSleepThread(100000);
}
