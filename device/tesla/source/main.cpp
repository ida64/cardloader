/* CardLoader as a Tesla overlay: the image library of the xci sysmodule,
 * the mounted image and the swap progress, over any screen.
 *
 *   Up/Down  move    A  mount the highlighted image (or run "Refresh")
 *   Y        refresh B  close the overlay
 *
 * IPC that can wait (SelectImageByIndex: pm queries, file opens; ListImages:
 * directory scan under the sysmodule's lock) runs on a worker thread. The
 * frame loop only reads GetStatus, which takes no lock in the sysmodule. */
#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include <atomic>
#include <cstring>

#include "xci_client.h"
#include "xci_view.h"

namespace {

    constexpr u32 StatusPollFrames = 15; /* ~250 ms at 60 fps */

    Result g_service_rc = -1;

    /* One IPC job at a time, off the frame loop. */
    class Worker {
        public:
            enum class Job { None, List, Select };

            struct ListResult {
                XciImageEntry entries[XCI_MAX_IMAGES];
                u32 total;
                char library[XCI_PATH_MAX];
            };

            ~Worker() {
                if (m_running) {
                    threadWaitForExit(&m_thread);
                    threadClose(&m_thread);
                }
            }

            bool Busy() const { return m_running; }

            bool StartList() { return Start(Job::List, 0); }
            bool StartSelect(u32 index) { return Start(Job::Select, index); }

            /* Frame loop: returns the finished job once, else Job::None. */
            Job Collect(Result *rc) {
                if (!m_running || !m_done.load(std::memory_order_acquire))
                    return Job::None;
                threadWaitForExit(&m_thread);
                threadClose(&m_thread);
                m_running = false;
                *rc = m_rc;
                return m_job;
            }

            const ListResult &List() const { return m_list; }

        private:
            bool Start(Job job, u32 index) {
                if (m_running)
                    return false;
                s32 prio = 0x2C;
                svcGetThreadPriority(&prio, CUR_THREAD_HANDLE);
                m_job = job;
                m_index = index;
                m_done.store(false, std::memory_order_relaxed);
                if (R_FAILED(threadCreate(&m_thread, Entry, this, nullptr, 0x4000, prio, -2)))
                    return false;
                if (R_FAILED(threadStart(&m_thread))) {
                    threadClose(&m_thread);
                    return false;
                }
                m_running = true;
                return true;
            }

            static void Entry(void *arg) {
                auto *self = static_cast<Worker *>(arg);
                if (self->m_job == Job::Select) {
                    self->m_rc = xciSelectImageByIndex(self->m_index);
                } else {
                    self->m_list.total = 0;
                    self->m_rc = xciListImages(self->m_list.entries, XCI_MAX_IMAGES, &self->m_list.total);
                    xciGetLibraryPath(self->m_list.library, sizeof(self->m_list.library));
                }
                self->m_done.store(true, std::memory_order_release);
            }

            Thread m_thread = {};
            Job m_job = Job::None;
            u32 m_index = 0;
            Result m_rc = 0;
            bool m_running = false;
            std::atomic<bool> m_done{false};
            ListResult m_list = {};
    };

    class GuiMain : public tsl::Gui {
        public:
            GuiMain() { xci_sel_init(&m_sel); }

            tsl::elm::Element *createUI() override {
                auto *frame = new tsl::elm::OverlayFrame("CardLoader", "\uE0A0 mount  \uE0A3 refresh  \uE0A1 close");
                m_list = new tsl::elm::List();
                Populate();
                frame->setContent(m_list);
                if (R_SUCCEEDED(g_service_rc))
                    m_worker.StartList();
                return frame;
            }

            void update() override {
                if (R_FAILED(g_service_rc))
                    return;

                Result rc = 0;
                bool poll_now = false;
                switch (m_worker.Collect(&rc)) {
                    case Worker::Job::Select: {
                        XciStatus st = {};
                        xciGetStatus(&st);
                        xci_sel_finish(&m_sel, rc, &st);
                        poll_now = true;
                        break;
                    }
                    case Worker::Job::List:
                        ApplyList(rc);
                        break;
                    case Worker::Job::None:
                        break;
                }

                if (poll_now || ++m_frames % StatusPollFrames == 0) {
                    XciStatus st = {};
                    if (R_SUCCEEDED(xciGetStatus(&st))) {
                        const xci_sel_phase_t before = m_sel.phase;
                        xci_sel_poll(&m_sel, &st);
                        m_card_text = xci_card_text(xci_card_state(&st));
                        /* A finished swap moves the current marker. */
                        if (before == XCI_SEL_SWAPPING && m_sel.phase != XCI_SEL_SWAPPING)
                            m_worker.StartList();
                    }
                    ShowStatus();
                }
            }

            bool handleInput(u64 keysDown, u64, const HidTouchState &, HidAnalogStickState, HidAnalogStickState) override {
                if (keysDown & HidNpadButton_Y) {
                    RequestList();
                    return true;
                }
                return false;
            }

        private:
            /* Rebuilds the list from m_entries. Items are deleted by the list
             * on its next draw, after the current input handler returns. */
            void Populate() {
                m_card = nullptr;
                m_message = nullptr;
                m_rows.clear();
                if (R_FAILED(g_service_rc)) {
                    char text[64];
                    std::snprintf(text, sizeof(text), "xci service unavailable (0x%x)", g_service_rc);
                    m_list->addItem(new tsl::elm::ListItem(text));
                    m_list->addItem(new tsl::elm::ListItem("Install the xci sysmodule (0100000000000422)"));
                    return;
                }
                m_list->addItem(new tsl::elm::CategoryHeader("Card"));
                m_card = new tsl::elm::ListItem("(none)", "starting");
                m_list->addItem(m_card);
                m_message = new tsl::elm::ListItem("Ready");
                m_list->addItem(m_message);
                auto *refresh = new tsl::elm::ListItem("Refresh", "\uE0A3");
                refresh->setClickListener([this](u64 keys) {
                    if (!(keys & HidNpadButton_A))
                        return false;
                    RequestList();
                    return true;
                });
                m_list->addItem(refresh);

                char header[XCI_PATH_MAX + 16];
                std::snprintf(header, sizeof(header), "Images in %s", m_library[0] ? m_library : "library");
                m_list->addItem(new tsl::elm::CategoryHeader(header));
                if (m_count == 0)
                    m_list->addItem(new tsl::elm::ListItem(m_loaded ? "No .xci or .xc0 images" : "Loading..."));
                for (u32 i = 0; i < m_count; i++) {
                    auto *row = new tsl::elm::ListItem("");
                    row->setClickListener([this, i](u64 keys) {
                        if (!(keys & HidNpadButton_A))
                            return false;
                        RequestSelect(i);
                        return true;
                    });
                    m_rows.push_back(row);
                    m_list->addItem(row);
                }
                ShowRows();
                ShowStatus();
            }

            void ShowRows() {
                for (u32 i = 0; i < m_rows.size() && i < m_count; i++) {
                    char label[XCI_NAME_MAX + 4], value[40];
                    xci_entry_label(&m_entries[i], label, sizeof(label));
                    xci_entry_value(&m_entries[i], value, sizeof(value));
                    m_rows[i]->setText(label);
                    m_rows[i]->setValue(value);
                }
            }

            void ShowStatus() {
                if (m_card == nullptr)
                    return;
                const int cur = xci_current_index(m_entries, m_count);
                m_card->setText(cur >= 0 ? m_entries[cur].name : "(none)");
                m_card->setValue(m_card_text);
                m_message->setText(m_note[0] ? m_note : (m_sel.message[0] ? m_sel.message : "Ready"));
            }

            void ApplyList(Result rc) {
                const auto &l = m_worker.List();
                m_loaded = true;
                if (R_FAILED(rc)) {
                    xci_error_describe(rc, m_note, sizeof(m_note));
                    ShowStatus();
                    return;
                }
                m_note[0] = 0;
                const u32 count = l.total < XCI_MAX_IMAGES ? l.total : XCI_MAX_IMAGES;
                const bool same_shape = count == m_count && count > 0 && std::strcmp(m_library, l.library) == 0;
                std::memcpy(m_entries, l.entries, sizeof(m_entries));
                m_count = count;
                std::strncpy(m_library, l.library, sizeof(m_library) - 1);
                if (same_shape) {
                    ShowRows();
                    ShowStatus();
                    return;
                }
                this->removeFocus();
                m_list->clear();
                Populate();
                this->restoreFocus();
            }

            void RequestList() {
                if (!m_worker.StartList())
                    std::snprintf(m_note, sizeof(m_note), "busy, try again");
                else
                    m_note[0] = 0;
                ShowStatus();
            }

            void RequestSelect(u32 index) {
                if (!xci_sel_can_start(&m_sel)) {
                    xci_error_describe(XCI_RESULT(XciError_Busy), m_note, sizeof(m_note));
                } else if (index < m_count && m_worker.StartSelect(index)) {
                    m_note[0] = 0;
                    xci_sel_start(&m_sel, m_entries[index].name);
                } else {
                    std::snprintf(m_note, sizeof(m_note), "busy, try again");
                }
                ShowStatus();
            }

            Worker m_worker;
            xci_sel_t m_sel;
            tsl::elm::List *m_list = nullptr;
            tsl::elm::ListItem *m_card = nullptr;
            tsl::elm::ListItem *m_message = nullptr;
            std::vector<tsl::elm::ListItem *> m_rows;
            XciImageEntry m_entries[XCI_MAX_IMAGES] = {};
            u32 m_count = 0;
            bool m_loaded = false;
            char m_library[XCI_PATH_MAX] = {};
            char m_note[160] = {};
            const char *m_card_text = "starting";
            u32 m_frames = 0;
    };

    class XciOverlay : public tsl::Overlay {
        public:
            void initServices() override { g_service_rc = xciInitialize(); }
            void exitServices() override {
                if (R_SUCCEEDED(g_service_rc))
                    xciExit();
            }
            std::unique_ptr<tsl::Gui> loadInitialGui() override { return initially<GuiMain>(); }
    };

}

int main(int argc, char **argv) {
    return tsl::loop<XciOverlay>(argc, argv);
}
