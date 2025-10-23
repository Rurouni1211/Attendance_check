#define SDL_MAIN_HANDLED
#include <httplib.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <qrencode.h>
#include <SDL.h>
#include <SDL_opengl.h>

#include <imgui.h>
// NOTE: these two are now included from IMGUI_BACKENDS_DIR added in CMake
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"

#include <iostream>
#include <chrono>
#include <ctime>
#include <string>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <random>
#include <atomic>
#include <thread>
#include <map>
#include <algorithm>
#include <vector>

using nlohmann::json;

// ---- QR timing & UI ----
static constexpr long SLOT_SECONDS = 120;   // each QR valid for 120s
static constexpr int  WINDOW_W = 1000;  // window width
static constexpr int  WINDOW_H = 700;   // window height

// ===================== General helpers =====================
static int exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) { std::cerr << "SQL error: " << (err ? err : "") << "\n"; sqlite3_free(err); }
    return rc;
}

std::string iso_now_utc() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm g{};
#if defined(_WIN32)
    gmtime_s(&g, &t);
#else
    g = *std::gmtime(&t);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &g);
    return buf;
}

time_t parse_iso_utc(const std::string& s) {
    if (s.size() < 20) return 0;
    std::tm tm{};
    tm.tm_year = std::stoi(s.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(s.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(s.substr(8, 2));
    tm.tm_hour = std::stoi(s.substr(11, 2));
    tm.tm_min = std::stoi(s.substr(14, 2));
    tm.tm_sec = std::stoi(s.substr(17, 2));
#if defined(_WIN32)
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

// ===================== QR / HMAC config =====================
static const std::string OFFICE_ID = "HQ-1";                         // change for your site
static const std::string OFFICE_SECRET = "change-me-please-32byte-min";  // strong secret!

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        mac, &len);
    std::ostringstream oss; oss << std::hex << std::setfill('0');
    for (unsigned i = 0; i < len; i++) oss << std::setw(2) << (int)mac[i];
    return oss.str();
}

std::string rand_hex(size_t nbytes = 8) {
    std::random_device rd; std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned> dist(0, 255);
    std::ostringstream oss; oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < nbytes; i++) oss << std::setw(2) << dist(gen);
    return oss.str();
}

struct QrBundle { std::string json; long slot; std::string nonce; };

// Current SLOT_SECONDS slot + signed JSON payload
QrBundle make_qr_payload() {
    long now = std::time(nullptr);
    long slot = now / SLOT_SECONDS;
    std::string nonce = rand_hex(8);
    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce;
    std::string sig = hmac_sha256_hex(OFFICE_SECRET, data);

    json j{
      {"ver",1},{"office_id",OFFICE_ID},{"slot",slot},{"nonce",nonce},{"sig",sig}
    };
    return { j.dump(), slot, nonce };
}

// ===================== libqrencode ¨ draw in ImGui =====================
struct QrPixels { int modules = 0, quiet = 4; std::vector<uint8_t> bits; };

QrPixels make_qr_pixels(const std::string& text, int quiet = 4) {
    QrPixels out;
    QRcode* qrc = QRcode_encodeString(text.c_str(), 0, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (!qrc) return out;
    out.modules = qrc->width; out.quiet = quiet;
    out.bits.resize(out.modules * out.modules);
    unsigned char* p = qrc->data;
    for (int y = 0; y < out.modules; ++y)
        for (int x = 0; x < out.modules; ++x, ++p)
            out.bits[y * out.modules + x] = ((*p) & 0x01) ? 1 : 0;
    QRcode_free(qrc);
    return out;
}

void imgui_draw_qr(const QrPixels& q, float sizePx) {
    if (q.modules <= 0) return;
    int total = q.modules + 2 * q.quiet;
    float scale = sizePx / (float)total;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    // white background
    dl->AddRectFilled(p0, ImVec2(p0.x + sizePx, p0.y + sizePx), IM_COL32(255, 255, 255, 255));

    // draw dots
    for (int y = 0; y < q.modules; ++y) {
        for (int x = 0; x < q.modules; ++x) {
            if (q.bits[y * q.modules + x]) {
                float rx = (x + q.quiet) * scale;
                float ry = (y + q.quiet) * scale;
                dl->AddRectFilled(
                    ImVec2(p0.x + rx, p0.y + ry),
                    ImVec2(p0.x + rx + scale, p0.y + ry + scale),
                    IM_COL32(0, 0, 0, 255));
            }
        }
    }
    ImGui::Dummy(ImVec2(sizePx, sizePx)); // advance cursor
}

// ===================== DB helpers: users + events =====================
struct User { int id; std::string name; double rate; };

std::vector<User> load_users(sqlite3* db) {
    std::vector<User> v;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT id,name,hourly_rate FROM users ORDER BY id ASC", -1, &s, nullptr) == SQLITE_OK) {
        while (sqlite3_step(s) == SQLITE_ROW) {
            v.push_back(User{
                sqlite3_column_int(s,0),
                reinterpret_cast<const char*>(sqlite3_column_text(s,1)),
                sqlite3_column_double(s,2)
                });
        }
        sqlite3_finalize(s);
    }
    return v;
}

bool insert_event(sqlite3* db, int user_id, const std::string& type, const std::string& device = "gui") {
    std::string ts = iso_now_utc();
    const char* SQL = "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_null(stmt, 4);
    sqlite3_bind_text(stmt, 5, device.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

// compute today's (UTC) work hours and break hours for a user
struct TodayStats { double work_hours = 0.0; double break_hours = 0.0; };

TodayStats compute_today(sqlite3* db, int user_id) {
    auto now = std::time(nullptr);
    std::tm g{};
#if defined(_WIN32)
    gmtime_s(&g, &now);
#else
    g = *std::gmtime(&now);
#endif
    char datebuf[11];
    std::strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", &g);
    std::string day = datebuf;

    const char* SQL =
        "SELECT type, ts_utc FROM events "
        "WHERE user_id=? AND substr(ts_utc,1,10)=? "
        "ORDER BY ts_utc ASC;";
    sqlite3_stmt* s = nullptr;
    TodayStats out{};
    if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return out;
    sqlite3_bind_int(s, 1, user_id);
    sqlite3_bind_text(s, 2, day.c_str(), -1, SQLITE_TRANSIENT);

    bool in_session = false, in_break = false;
    time_t t_in = 0, t_break_start = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        std::string type = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        std::string ts = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        time_t t = parse_iso_utc(ts);
        if (type == "IN") {
            if (!in_session) { in_session = true; t_in = t; }
        }
        else if (type == "BREAK_START") {
            if (in_session && !in_break) { in_break = true; t_break_start = t; }
        }
        else if (type == "BREAK_END") {
            if (in_session && in_break) {
                out.break_hours += double(t - t_break_start) / 3600.0;
                t_in += (t - t_break_start); // shift start forward so OUT-IN subtracts breaks
                in_break = false; t_break_start = 0;
            }
        }
        else if (type == "OUT") {
            if (in_session) {
                if (in_break) { // auto-close break at OUT
                    out.break_hours += double(t - t_break_start) / 3600.0;
                    t_in += (t - t_break_start);
                    in_break = false; t_break_start = 0;
                }
                out.work_hours += std::max(0.0, double(t - t_in) / 3600.0);
                in_session = false; t_in = 0;
            }
        }
    }
    sqlite3_finalize(s);
    return out;
}

// ===================== HTTP server (same endpoints) =====================
void run_server(sqlite3* db, std::atomic<bool>& server_ok) {
    try {
        httplib::Server svr;
        svr.set_logger([](const auto& req, const auto& res) {
            std::cout << req.method << " " << req.path << " -> " << res.status << "\n";
            });

        svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("{\"ok\":true}", "application/json");
            });

        // expose current QR payload (for mobile dev)
        svr.Get("/api/qr/current", [](const httplib::Request&, httplib::Response& res) {
            auto qb = make_qr_payload();
            res.set_content(qb.json, "application/json");
            });

        // POST /api/events
        svr.Post("/api/events", [db](const httplib::Request& req, httplib::Response& res) {
            try {
                if (req.get_header_value("Content-Type").find("application/json") == std::string::npos &&
                    req.get_header_value("content-type").find("application/json") == std::string::npos) {
                    res.status = 400; res.set_content(R"({"error":"Content-Type must be application/json"})", "application/json"); return;
                }
                json body = json::parse(req.body);

                if (!body.contains("userId") || !body["userId"].is_number_integer()) {
                    res.status = 400; res.set_content(R"({"error":"userId (integer) is required"})", "application/json"); return;
                }
                if (!body.contains("type") || !body["type"].is_string()) {
                    res.status = 400; res.set_content(R"({"error":"type (string) is required"})", "application/json"); return;
                }

                const int user_id = body["userId"].get<int>();
                const std::string type = body["type"].get<std::string>();

                static const std::unordered_set<std::string> kAllowed{ "IN","OUT","BREAK_START","BREAK_END" };
                if (!kAllowed.count(type)) {
                    res.status = 400; res.set_content(R"({"error":"type must be IN|OUT|BREAK_START|BREAK_END"})", "application/json"); return;
                }

                // insert event
                std::string ts_utc = iso_now_utc();
                std::string ts_local = body.value("tsLocal", "");
                std::string device_id = body.value("deviceId", "");
                const char* SQL = "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
                    res.status = 500; res.set_content(R"({"error":"prepare failed"})", "application/json"); return;
                }
                sqlite3_bind_int(stmt, 1, user_id);
                sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, ts_utc.c_str(), -1, SQLITE_TRANSIENT);
                if (!ts_local.empty()) sqlite3_bind_text(stmt, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT); else sqlite3_bind_null(stmt, 4);
                if (!device_id.empty()) sqlite3_bind_text(stmt, 5, device_id.c_str(), -1, SQLITE_TRANSIENT); else sqlite3_bind_null(stmt, 5);
                bool ok = sqlite3_step(stmt) == SQLITE_DONE; sqlite3_finalize(stmt);
                if (!ok) { res.status = 500; res.set_content(R"({"error":"insert failed"})", "application/json"); return; }

                json out = { {"ok",true},{"userId",user_id},{"type",type},{"ts_utc",ts_utc} };
                res.set_content(out.dump(), "application/json");
            }
            catch (const std::exception& e) {
                json err = { {"error","invalid JSON"}, {"detail", e.what()} };
                res.status = 400; res.set_content(err.dump(), "application/json");
            }
            });

        // simple reads
        svr.Get("/api/events/recent", [db](const httplib::Request&, httplib::Response& res) {
            const char* SQL = "SELECT id,user_id,type,ts_utc,ts_local,device_id FROM events ORDER BY id DESC LIMIT 20;";
            sqlite3_stmt* stmt = nullptr; json out = json::array();
            if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    json row;
                    row["id"] = sqlite3_column_int64(stmt, 0);
                    row["userId"] = sqlite3_column_int(stmt, 1);
                    row["type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                    row["ts_utc"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                    if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) row["ts_local"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                    if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) row["deviceId"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                    out.push_back(row);
                }
                sqlite3_finalize(stmt);
            }
            res.set_content(out.dump(), "application/json");
            });

        if (!svr.bind_to_port("0.0.0.0", 8080)) { std::cerr << "HTTP bind failed\n"; server_ok.store(false); return; }
        server_ok.store(true);
        svr.listen_after_bind();
    }
    catch (...) { server_ok.store(false); }
}

// ===================== main =====================
int main() {
    // DB bootstrap
    sqlite3* db = nullptr;
    if (sqlite3_open("attendance.db", &db) != SQLITE_OK) { std::cerr << "Failed to open DB\n"; return 1; }
    const char* DDL =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS users("
        " id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " hourly_rate REAL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS events("
        " id INTEGER PRIMARY KEY,"
        " user_id INTEGER NOT NULL,"
        " type TEXT NOT NULL,"
        " ts_utc TEXT NOT NULL,"
        " ts_local TEXT,"
        " device_id TEXT);"
        "CREATE TABLE IF NOT EXISTS used_nonces("
        " office_id TEXT NOT NULL,"
        " slot INTEGER NOT NULL,"
        " nonce TEXT NOT NULL,"
        " PRIMARY KEY(office_id,slot,nonce));"
        "INSERT INTO users(id,name,hourly_rate)"
        " SELECT 1,'Demo User',1200.0"
        " WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=1);";
    if (exec_sql(db, DDL) != SQLITE_OK) return 1;

    // Start HTTP server in background
    std::atomic<bool> http_ok{ false };
    std::thread http_thread(run_server, db, std::ref(http_ok));

    // GUI: SDL + OpenGL + ImGui
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO) != 0) { std::cerr << "SDL_Init: " << SDL_GetError() << "\n"; return 1; }
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_Window* window = SDL_CreateWindow(
        "Attendance Console",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        WINDOW_W, WINDOW_H,
        SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    if (!window) { std::cerr << "SDL_CreateWindow failed\n"; return 1; }
    SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_ctx);
    SDL_GL_SetSwapInterval(1); // vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
    ImGui_ImplOpenGL3_Init("#version 130"); // GL 3.0+

    // load users
    std::vector<User> users = load_users(db);
    int selected_user_idx = users.empty() ? -1 : 0;

    // initial QR
    auto qrBundle = make_qr_payload();
    auto qrPix = make_qr_pixels(qrBundle.json);
    long lastSlot = qrBundle.slot;

    bool running = true;
    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            ImGui_ImplSDL2_ProcessEvent(&e);
            if (e.type == SDL_QUIT) running = false;
            if (e.type == SDL_WINDOWEVENT && e.window.event == SDL_WINDOWEVENT_CLOSE && e.window.windowID == SDL_GetWindowID(window))
                running = false;
        }

        // regenerate QR when slot changes
        long curSlot = std::time(nullptr) / SLOT_SECONDS;
        if (curSlot != lastSlot) {
            qrBundle = make_qr_payload();
            qrPix = make_qr_pixels(qrBundle.json);
            lastSlot = curSlot;
        }

        // start frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        // Main window
        ImGui::Begin("Attendance Console");
        ImGui::Text("Server: %s", http_ok.load() ? "listening on :8080" : "starting...");

        // User selector
        if (ImGui::CollapsingHeader("Employee", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (users.empty()) {
                ImGui::TextWrapped("No users yet. Using Demo User (id=1). Add more in the DB (table: users).");
            }
            else {
                const char* current = users[selected_user_idx < 0 ? 0 : selected_user_idx].name.c_str();
                if (ImGui::BeginCombo("User", current)) {
                    for (int i = 0; i < (int)users.size(); ++i) {
                        bool sel = (i == selected_user_idx);
                        if (ImGui::Selectable(users[i].name.c_str(), sel)) selected_user_idx = i;
                        if (sel) ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
                if (selected_user_idx >= 0) {
                    ImGui::Text("Hourly rate: %.2f", users[selected_user_idx].rate);
                }
            }
        }

        // Today stats + controls
        if (ImGui::CollapsingHeader("Today", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (selected_user_idx >= 0) {
                auto stats = compute_today(db, users[selected_user_idx].id);
                ImGui::Text("Working: %.2f h", stats.work_hours);
                ImGui::Text("Break:   %.2f h", stats.break_hours);
                ImGui::Separator();

                // Buttons row
                if (ImGui::Button("Check In")) { insert_event(db, users[selected_user_idx].id, "IN"); }
                ImGui::SameLine();
                if (ImGui::Button("Break Start")) { insert_event(db, users[selected_user_idx].id, "BREAK_START"); }
                ImGui::SameLine();
                if (ImGui::Button("Break End")) { insert_event(db, users[selected_user_idx].id, "BREAK_END"); }
                ImGui::SameLine();
                if (ImGui::Button("Check Out")) { insert_event(db, users[selected_user_idx].id, "OUT"); }
                ImGui::SameLine();
                if (ImGui::Button("Reload Users")) {
                    users = load_users(db);
                    if (selected_user_idx >= (int)users.size()) selected_user_idx = users.empty() ? -1 : 0;
                }
            }
            else {
                ImGui::Text("Select a user above.");
            }
        }

        // QR panel
        if (ImGui::CollapsingHeader("QR (scan in-office)", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Text("Office: %s", OFFICE_ID.c_str());
            ImGui::Text("Slot seconds: %ld", SLOT_SECONDS);
            ImGui::Text("Payload (debug):");
            ImGui::BeginChild("qrpayload", ImVec2(0, 80), true);
            ImGui::TextWrapped("%s", qrBundle.json.c_str());
            ImGui::EndChild();

            ImGui::Text("Code:");
            imgui_draw_qr(qrPix, 260.0f); // 260px square QR
        }

        ImGui::End();

        // render
        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.08f, 0.08f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();

    // stop HTTP (process exit will reclaim thread/resources)
    if (http_thread.joinable()) http_thread.detach();
    sqlite3_close(db);
    return 0;
}
