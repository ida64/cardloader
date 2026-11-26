/* xci_ipc.h - the "xci" service as clients see it (C, shared by the
 * sysmodule, the switcher NRO and the host tests).
 *
 * Command 0 is the FS hook's GetWindow and is unchanged. Image names are
 * "name.xci" for a single file, "name" for a split name.xc0 (+ name.xc1)
 * pair. Paths are "sdmc:/..." or relative to the library directory. The slot
 * is empty at boot; nothing is inserted until a client selects an image.
 */
#ifndef XCI_IPC_H
#define XCI_IPC_H

#include <stdint.h>

#define XCI_SERVICE_NAME "xci"
#define XCI_NAME_MAX     0x80  /* image name incl. NUL */
#define XCI_PATH_MAX     0x300 /* path incl. NUL */
#define XCI_MAX_IMAGES   64    /* entries one directory scan keeps */

enum {
    XciCmd_GetWindow          = 0, /* out copy handle: the shared window (FS hook) */
    XciCmd_ListImages         = 1, /* out u32 total, out buffer XciImageEntry[] (sorted by name) */
    XciCmd_GetStatus          = 2, /* out XciStatus */
    XciCmd_GetCurrentImage    = 3, /* out buffer XciImageEntry (name empty: no image) */
    XciCmd_SelectImageByIndex = 4, /* in u32 index into ListImages' order */
    XciCmd_SelectImageByPath  = 5, /* in buffer path (NUL-terminated) */
    XciCmd_GetLibraryPath     = 6, /* out buffer path of the library directory */
};

#define XCI_IMAGE_FLAG_CURRENT 1u /* the image the card currently holds or is swapping to */

typedef struct {
    char name[XCI_NAME_MAX];
    uint64_t size;   /* bytes, all parts */
    uint32_t parts;  /* 1 (.xci or .xc0 alone) or 2 (.xc0 + .xc1) */
    uint32_t flags;  /* XCI_IMAGE_FLAG_* */
} XciImageEntry;

typedef struct {
    uint32_t stage;          /* hh_window_t.stage (HH_STAGE_*) */
    uint32_t swap_req;       /* last select's generation */
    uint32_t swap_done;      /* == swap_req once the sysmodule switched files */
    int32_t  mount_code;     /* 0 inserting, 256 mounted, -1 none/failed */
    uint32_t exec_count;     /* ASIC operations the hook served */
    uint32_t presence_calls; /* FS inserted-predicate calls */
    uint32_t presence_hits;  /* of those, answered "inserted" */
    uint32_t window_requests;/* GetWindow calls (the hook found us) */
} XciStatus;

/* Results: module 505, descriptions below. */
#define XCI_RESULT_MODULE 505u
#define XCI_RESULT(desc) (XCI_RESULT_MODULE | ((uint32_t)(desc) << 9))
enum {
    XciError_InvalidIndex  = 1, /* index outside the current listing */
    XciError_InvalidPath   = 2, /* not an .xci / .xc0 / split base path */
    XciError_OpenFailed    = 3, /* file missing or unreadable */
    XciError_Busy          = 4, /* a swap is still in progress */
    XciError_GameCardInUse = 5, /* an application launched from the game card is running */
    XciError_ListFailed    = 6, /* library directory unreadable */
    XciError_NotAnImage    = 7, /* no XCI card header ("HEAD" at 0x100) */
};

#endif /* XCI_IPC_H */
