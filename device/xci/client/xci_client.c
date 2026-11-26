/* xci_client.c - see xci_client.h. */
#include <string.h>
#include "xci_client.h"

static Service g_xci;

Result xciInitialize(void)
{
    return smGetService(&g_xci, XCI_SERVICE_NAME);
}

void xciExit(void)
{
    serviceClose(&g_xci);
}

Result xciListImages(XciImageEntry *out, u32 max, u32 *total)
{
    return serviceDispatchOut(&g_xci, XciCmd_ListImages, *total,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out, max * sizeof(XciImageEntry) } });
}

Result xciGetStatus(XciStatus *out)
{
    return serviceDispatchOut(&g_xci, XciCmd_GetStatus, *out);
}

Result xciGetCurrentImage(XciImageEntry *out)
{
    return serviceDispatch(&g_xci, XciCmd_GetCurrentImage,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out, sizeof(*out) } });
}

Result xciSelectImageByIndex(u32 index)
{
    return serviceDispatchIn(&g_xci, XciCmd_SelectImageByIndex, index);
}

Result xciSelectImageByPath(const char *path)
{
    return serviceDispatch(&g_xci, XciCmd_SelectImageByPath,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { path, strlen(path) + 1 } });
}

Result xciGetLibraryPath(char *out, size_t size)
{
    memset(out, 0, size);
    return serviceDispatch(&g_xci, XciCmd_GetLibraryPath,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out, size } });
}
