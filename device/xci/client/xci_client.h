/* xci_client.h - libnx client for the "xci" sysmodule (commands: xci_ipc.h).
 * Userland only (sm + IPC): used by the switcher NRO and the Tesla overlay.
 * Presentation helpers that need no libnx live in xci_view.h. */
#ifndef XCI_CLIENT_H
#define XCI_CLIENT_H

#include <switch.h>
#include "xci_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

Result xciInitialize(void);
void xciExit(void);

/* Fills up to max entries (sorted by name); *total is the full count. */
Result xciListImages(XciImageEntry *out, u32 max, u32 *total);
Result xciGetStatus(XciStatus *out);
Result xciGetCurrentImage(XciImageEntry *out);
Result xciSelectImageByIndex(u32 index);
Result xciSelectImageByPath(const char *path);
Result xciGetLibraryPath(char *out, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* XCI_CLIENT_H */
