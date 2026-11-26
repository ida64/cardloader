#include "mount.h"

void gc_mount_init(gc_mount_t *m, gc_pulse_fn pulse, void *ctx)
{
    memset(m, 0, sizeof(*m));
    m->status = GC_MOUNT_IDLE;
    m->pulse = pulse;
    m->pulse_ctx = ctx;
}

int gc_mount_request(gc_mount_t *m, const char *path, bool physical_present)
{
    if (!m || !path || !path[0])
        return -1;
    if (physical_present)
        return -1;
    size_t n = strlen(path);
    if (n >= sizeof(m->path))
        return -1;
    memcpy(m->path, path, n + 1);
    m->status = GC_MOUNT_PENDING;
    m->countdown = GC_MOUNT_TICKS;
    m->insert_pulsed = false;
    if (m->pulse)
        m->pulse(m->pulse_ctx);
    return 0;
}

int gc_mount_tick(gc_mount_t *m)
{
    if (!m || m->status != GC_MOUNT_PENDING)
        return 0;
    if (m->countdown > 0)
        m->countdown--;
    if (m->countdown == 0 && !m->insert_pulsed) {
        m->insert_pulsed = true;
        if (m->pulse)
            m->pulse(m->pulse_ctx);
        return 1;
    }
    return 0;
}

void gc_mount_result(gc_mount_t *m, bool ok)
{
    if (!m || m->status != GC_MOUNT_PENDING)
        return;
    m->status = ok ? GC_MOUNT_MOUNTED : GC_MOUNT_FAILED;
}

bool gc_card_present(const gc_mount_t *m, bool gpio_line_low)
{
    if (gpio_line_low) /* active low: a real cartridge shorts the pin */
        return true;
    if (m->status == GC_MOUNT_PENDING && m->countdown > 0)
        return false;
    return m->path[0] != 0;
}

int gc_mount_code(const gc_mount_t *m)
{
    if (!m)
        return GC_STATUS_FAILED;
    switch (m->status) {
    case GC_MOUNT_PENDING:
        return GC_STATUS_PENDING;
    case GC_MOUNT_MOUNTED:
        return GC_STATUS_MOUNTED;
    default:
        return GC_STATUS_FAILED;
    }
}
