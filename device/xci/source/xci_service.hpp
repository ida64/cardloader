#pragma once
#include <stratosphere.hpp>
#include "xci_ipc.h"

/* Command table: xci_ipc.h. Command 0 is the FS hook's and is unchanged. */
#define AMS_XCI_I_SERVICE_INTERFACE_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, GetWindow,          (sf::OutCopyHandle out_handle),                                              (out_handle))          \
    AMS_SF_METHOD_INFO(C, H, 1, Result, ListImages,         (sf::Out<u32> out_total, const sf::OutMapAliasArray<XciImageEntry> &out_entries),   (out_total, out_entries)) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, GetStatus,          (sf::Out<XciStatus> out),                                                    (out))                 \
    AMS_SF_METHOD_INFO(C, H, 3, Result, GetCurrentImage,    (const sf::OutBuffer &out),                                                  (out))                 \
    AMS_SF_METHOD_INFO(C, H, 4, Result, SelectImageByIndex, (u32 index),                                                                 (index))               \
    AMS_SF_METHOD_INFO(C, H, 5, Result, SelectImageByPath,  (const sf::InBuffer &path),                                                  (path))                \
    AMS_SF_METHOD_INFO(C, H, 6, Result, GetLibraryPath,     (const sf::OutBuffer &out),                                                  (out))

AMS_SF_DEFINE_INTERFACE(ams::xci::impl, IService, AMS_XCI_I_SERVICE_INTERFACE_INFO, 0x00000000)

R_DEFINE_NAMESPACE_RESULT_MODULE(ams::xci, 505);

namespace ams::xci {

    /* Descriptions match XciError_* in xci_ipc.h. */
    R_DEFINE_ERROR_RESULT(InvalidIndex,  1);
    R_DEFINE_ERROR_RESULT(InvalidPath,   2);
    R_DEFINE_ERROR_RESULT(OpenFailed,    3);
    R_DEFINE_ERROR_RESULT(Busy,          4);
    R_DEFINE_ERROR_RESULT(GameCardInUse, 5);
    R_DEFINE_ERROR_RESULT(ListFailed,    6);
    R_DEFINE_ERROR_RESULT(NotAnImage,    7);

    extern os::NativeHandle g_shmem_handle;
    extern std::atomic<u32> g_window_requests; /* GetWindow calls served: the FS hook reached us */

    /* Implemented in xci_main.cpp, over the library state it owns. */
    Result ListImages(u32 *out_total, XciImageEntry *out, size_t count);
    void GetStatus(XciStatus *out);
    void GetCurrentImage(XciImageEntry *out);
    Result SelectImageByIndex(u32 index);
    Result SelectImageByPath(const char *path);
    void GetLibraryPath(char *out, size_t size);

    class Service {
        public:
            Result GetWindow(sf::OutCopyHandle out_handle);
            Result ListImages(sf::Out<u32> out_total, const sf::OutMapAliasArray<XciImageEntry> &out_entries);
            Result GetStatus(sf::Out<XciStatus> out);
            Result GetCurrentImage(const sf::OutBuffer &out);
            Result SelectImageByIndex(u32 index);
            Result SelectImageByPath(const sf::InBuffer &path);
            Result GetLibraryPath(const sf::OutBuffer &out);
    };
    static_assert(impl::IsIService<Service>);

}
