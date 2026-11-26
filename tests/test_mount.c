#include <stdio.h>
#include "mount.h"

static int fails;
static int pulses;

static void pulse(void *ctx) { (void)ctx; pulses++; }

static void chk(const char *what, int ok)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        fails++;
}

int main(void)
{
    gc_mount_t m;
    gc_mount_init(&m, pulse, NULL);
    pulses = 0;

    chk("idle is not inserted", gc_card_present(&m, false) == false);
    chk("idle status is failed", gc_mount_code(&m) == GC_STATUS_FAILED);

    chk("physical card rejects mount",
        gc_mount_request(&m, "game.xci", true) == -1);
    chk("rejected mount leaves no path", m.path[0] == 0);

    chk("request accepted", gc_mount_request(&m, "game.xci", false) == 0);
    chk("removal pulse emitted", pulses == 1);
    chk("not inserted during countdown", gc_card_present(&m, false) == false);
    chk("physical line still wins", gc_card_present(&m, true) == true);
    chk("status pending", gc_mount_code(&m) == GC_STATUS_PENDING);

    int inserted_at = -1;
    for (int i = 1; i <= GC_MOUNT_TICKS; i++) {
        if (gc_mount_tick(&m))
            inserted_at = i;
    }
    chk("insertion pulse on last tick", inserted_at == GC_MOUNT_TICKS);
    chk("two pulses total", pulses == 2);
    chk("no extra pulse after countdown", gc_mount_tick(&m) == 0 && pulses == 2);
    chk("inserted after countdown", gc_card_present(&m, false) == true);

    gc_mount_result(&m, true);
    chk("status mounted is 256", gc_mount_code(&m) == GC_STATUS_MOUNTED);
    chk("mounted stays inserted", gc_card_present(&m, false) == true);

    gc_mount_t f;
    gc_mount_init(&f, pulse, NULL);
    gc_mount_request(&f, "broken.xci", false);
    for (int i = 0; i < GC_MOUNT_TICKS; i++)
        gc_mount_tick(&f);
    gc_mount_result(&f, false);
    chk("failed status is -1", gc_mount_code(&f) == GC_STATUS_FAILED);

    if (fails) {
        printf("\n%d FAILURE(S)\n", fails);
        return 1;
    }
    printf("\nall mount checks pass\n");
    return 0;
}
