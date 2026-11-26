#include <stratosphere.hpp>
#include "xci_service.hpp"

namespace ams::xci {

    Result Service::GetWindow(sf::OutCopyHandle out_handle) {
        g_window_requests++;
        out_handle.SetValue(g_shmem_handle, false);
        return ResultSuccess();
    }

    Result Service::ListImages(sf::Out<u32> out_total, const sf::OutMapAliasArray<XciImageEntry> &out_entries) {
        u32 total = 0;
        R_TRY(xci::ListImages(std::addressof(total), out_entries.GetPointer(), out_entries.GetSize()));
        out_total.SetValue(total);
        R_SUCCEED();
    }

    Result Service::GetStatus(sf::Out<XciStatus> out) {
        XciStatus st;
        xci::GetStatus(std::addressof(st));
        out.SetValue(st);
        R_SUCCEED();
    }

    Result Service::GetCurrentImage(const sf::OutBuffer &out) {
        R_UNLESS(out.GetSize() >= sizeof(XciImageEntry), xci::ResultInvalidPath());
        XciImageEntry e;
        xci::GetCurrentImage(std::addressof(e));
        std::memcpy(out.GetPointer(), std::addressof(e), sizeof(e));
        R_SUCCEED();
    }

    Result Service::SelectImageByIndex(u32 index) {
        R_RETURN(xci::SelectImageByIndex(index));
    }

    Result Service::SelectImageByPath(const sf::InBuffer &path) {
        char buf[XCI_PATH_MAX];
        const size_t n = std::min(path.GetSize(), sizeof(buf) - 1);
        std::memcpy(buf, path.GetPointer(), n);
        buf[n] = 0;
        R_RETURN(xci::SelectImageByPath(buf));
    }

    Result Service::GetLibraryPath(const sf::OutBuffer &out) {
        R_UNLESS(out.GetSize() > 0, xci::ResultInvalidPath());
        xci::GetLibraryPath(reinterpret_cast<char *>(out.GetPointer()), out.GetSize());
        R_SUCCEED();
    }

}
