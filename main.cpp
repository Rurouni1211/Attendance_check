#define SDL_MAIN_HANDLED
#include <httplib.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <qrencode.h>
#include <SDL.h>

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

using nlohmann::json;

// ===================== General helpers =====================
static int exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << (err ? err : "") << "\n";
        sqlite3_free(err);
    }
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
    // Very basic parser for "YYYY-MM-DDTHH:MM:SSZ"
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

// Current 30s slot + signed JSON payload
QrBundle make_qr_payload() {
    long now = std::time(nullptr);
    long slot = now / 30; // 30-second buckets
    std::string nonce = rand_hex(8);
    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce;
    std::string sig = hmac_sha256_hex(OFFICE_SECRET, data);

    json j{
      {"ver",1},{"office_id",OFFICE_ID},{"slot",slot},{"nonce",nonce},{"sig",sig}
    };
    return { j.dump(), slot, nonce };
}

// ===================== libqrencode + SDL2 drawing =====================
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

void render_qr(SDL_Renderer* r, const QrPixels& q, int winW, int winH) {
    if (q.modules <= 0) return;
    int total = q.modules + 2 * q.quiet;
    int scale = std::max(2, std::min(winW, winH) / total);
    int imgW = total * scale, imgH = total * scale;
    int offX = (winW - imgW) / 2, offY = (winH - imgH) / 2;

    SDL_SetRenderDrawColor(r, 17, 17, 17, 255); SDL_RenderClear(r);
    SDL_SetRenderDrawColor(r, 255, 255, 255, 255);
    SDL_Rect bg{ offX, offY, imgW, imgH }; SDL_RenderFillRect(r, &bg);
    SDL_SetRenderDrawColor(r, 0, 0, 0, 255);
    for (int y = 0; y < q.modules; ++y)
        for (int x = 0; x < q.modules; ++x)
            if (q.bits[y * q.modules + x]) {
                SDL_Rect dot{ offX + (x + q.quiet) * scale, offY + (y + q.quiet) * scale, scale, scale };
                SDL_RenderFillRect(r, &dot);
            }
}

void qr_window_thread(std::atomic<bool>& running) {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        std::cerr << "SDL_Init error: " << SDL_GetError() << "\n"; return;
    }
    SDL_Window* win = SDL_CreateWindow("Attendance QR", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 900, 900, SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
    if (!win) { std::cerr << "SDL_CreateWindow error: " << SDL_GetError() << "\n"; SDL_Quit(); return; }
    SDL_Renderer* ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!ren) { std::cerr << "SDL_CreateRenderer error: " << SDL_GetError() << "\n"; SDL_DestroyWindow(win); SDL_Quit(); return; }

    auto bundle = make_qr_payload();
    auto qrPix = make_qr_pixels(bundle.json);
    auto lastRefresh = std::chrono::steady_clock::now();

    while (running.load()) {
        SDL_Event e; while (SDL_PollEvent(&e)) if (e.type == SDL_QUIT) running.store(false);

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastRefresh).count() >= 5) {
            bundle = make_qr_payload();
            qrPix = make_qr_pixels(bundle.json);
            lastRefresh = now;
        }
        int w, h; SDL_GetRendererOutputSize(ren, &w, &h);
        render_qr(ren, qrPix, w, h);
        SDL_RenderPresent(ren);
    }
    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    SDL_Quit();
}

// ===================== main (DB + HTTP + QR GUI) =====================
int main() {
    // 1) DB bootstrap
    sqlite3* db = nullptr;
    if (sqlite3_open("attendance.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open DB\n"; return 1;
    }

    const char* DDL =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS users("
        " id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " hourly_rate REAL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS events("
        " id INTEGER PRIMARY KEY,"
        " user_id INTEGER NOT NULL,"
        " type TEXT NOT NULL,"
        " ts_utc TEXT NOT NULL,"
        " ts_local TEXT,"
        " device_id TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS used_nonces("
        " office_id TEXT NOT NULL,"
        " slot INTEGER NOT NULL,"
        " nonce TEXT NOT NULL,"
        " PRIMARY KEY(office_id,slot,nonce)"
        ");"
        "INSERT INTO users(id,name,hourly_rate)"
        " SELECT 1,'Demo User',1200.0"
        " WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=1);";
    if (exec_sql(db, DDL) != SQLITE_OK) return 1;

    // 2) Start QR window
    std::atomic<bool> running{ true };
    std::thread ui(qr_window_thread, std::ref(running));

    // 3) HTTP server
    httplib::Server svr;

    // request log
    svr.set_logger([](const auto& req, const auto& res) {
        std::cout << req.method << " " << req.path << " -> " << res.status << "\n";
        });

    // Health
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"ok\":true}", "application/json");
        });

    // Return current QR payload (debug/for mobile dev)
    svr.Get("/api/qr/current", [](const httplib::Request&, httplib::Response& res) {
        auto qb = make_qr_payload();
        res.set_content(qb.json, "application/json");
        });

    // JSON punch:
    // {
    //   "userId": 1,
    //   "type": "IN" | "OUT" | "BREAK_START" | "BREAK_END",
    //   "tsLocal": "...",            // optional
    //   "deviceId": "phone-abc",     // optional
    //   "qr": { "ver":1,"office_id":"HQ-1","slot":..., "nonce":"...", "sig":"..." }  // required if you want office verification
    // }
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

            // ========== optional QR verification ==========
            if (body.contains("qr")) {
                auto qr = body["qr"];
                std::string office_id = qr.value("office_id", "");
                long slot = qr.value("slot", 0L);
                std::string nonce = qr.value("nonce", "");
                std::string sig = qr.value("sig", "");

                if (office_id != OFFICE_ID) {
                    res.status = 400; res.set_content(R"({"error":"office mismatch"})", "application/json"); return;
                }
                long now_slot = std::time(nullptr) / 30;
                if (std::llabs(now_slot - slot) > 1) {   // Å}1 slot tolerance
                    res.status = 400; res.set_content(R"({"error":"qr stale"})", "application/json"); return;
                }
                std::string data = office_id + "|" + std::to_string(slot) + "|" + nonce;
                std::string expect = hmac_sha256_hex(OFFICE_SECRET, data);
                auto eq_ci = [](char a, char b) { return std::tolower(a) == std::tolower(b); };
                if (!std::equal(expect.begin(), expect.end(), sig.begin(), sig.end(), eq_ci)) {
                    res.status = 400; res.set_content(R"({"error":"bad signature"})", "application/json"); return;
                }
                // replay protect
                const char* INS = "INSERT INTO used_nonces(office_id,slot,nonce) VALUES(?,?,?);";
                sqlite3_stmt* s = nullptr;
                if (sqlite3_prepare_v2(db, INS, -1, &s, nullptr) != SQLITE_OK) {
                    res.status = 500; res.set_content(R"({"error":"nonce prepare"})", "application/json"); return;
                }
                sqlite3_bind_text(s, 1, office_id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(s, 2, slot);
                sqlite3_bind_text(s, 3, nonce.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(s) != SQLITE_DONE) {
                    sqlite3_finalize(s);
                    res.status = 400; res.set_content(R"({"error":"replay detected"})", "application/json"); return;
                }
                sqlite3_finalize(s);
            }
            // ==============================================

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
            if (!ts_local.empty()) sqlite3_bind_text(stmt, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_bind_null(stmt, 4);
            if (!device_id.empty()) sqlite3_bind_text(stmt, 5, device_id.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_bind_null(stmt, 5);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                sqlite3_finalize(stmt);
                res.status = 500; res.set_content(R"({"error":"insert failed"})", "application/json"); return;
            }
            const int64_t last_id = sqlite3_last_insert_rowid(db);
            sqlite3_finalize(stmt);

            json ok = {
              {"ok", true},
              {"id", last_id},
              {"userId", user_id},
              {"type", type},
              {"ts_utc", ts_utc}
            };
            if (!ts_local.empty())  ok["ts_local"] = ts_local;
            if (!device_id.empty()) ok["deviceId"] = device_id;

            res.set_content(ok.dump(), "application/json");
        }
        catch (const std::exception& e) {
            json err = { {"error","invalid JSON"}, {"detail", e.what()} };
            res.status = 400; res.set_content(err.dump(), "application/json");
        }
        });

    // Read endpoints
    svr.Get("/api/events/recent", [db](const httplib::Request&, httplib::Response& res) {
        const char* SQL = "SELECT id,user_id,type,ts_utc,ts_local,device_id FROM events ORDER BY id DESC LIMIT 20;";
        sqlite3_stmt* stmt = nullptr;
        json out = json::array();
        if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                json row;
                row["id"] = sqlite3_column_int64(stmt, 0);
                row["userId"] = sqlite3_column_int(stmt, 1);
                row["type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                row["ts_utc"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                if (sqlite3_column_type(stmt, 4) != SQLITE_NULL)
                    row["ts_local"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                if (sqlite3_column_type(stmt, 5) != SQLITE_NULL)
                    row["deviceId"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                out.push_back(row);
            }
            sqlite3_finalize(stmt);
        }
        res.set_content(out.dump(), "application/json");
        });

    svr.Get("/api/events/today", [db](const httplib::Request&, httplib::Response& res) {
        auto now = std::time(nullptr);
        std::tm g{};
#if defined(_WIN32)
        gmtime_s(&g, &now);
#else
        g = *std::gmtime(&now);
#endif
        char datebuf[11];
        std::strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", &g);
        std::string prefix = std::string(datebuf);

        const char* SQL = "SELECT id,user_id,type,ts_utc,ts_local,device_id "
            "FROM events WHERE ts_utc LIKE ? || '%' ORDER BY id ASC;";
        sqlite3_stmt* stmt = nullptr;
        json out = json::array();
        if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, prefix.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                json row;
                row["id"] = sqlite3_column_int64(stmt, 0);
                row["userId"] = sqlite3_column_int(stmt, 1);
                row["type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                row["ts_utc"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                if (sqlite3_column_type(stmt, 4) != SQLITE_NULL)
                    row["ts_local"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                if (sqlite3_column_type(stmt, 5) != SQLITE_NULL)
                    row["deviceId"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                out.push_back(row);
            }
            sqlite3_finalize(stmt);
        }
        res.set_content(out.dump(), "application/json");
        });

    // Payroll: GET /api/payroll/summary?userId=1&from=2025-10-01&to=2025-10-31
    struct DaySummary { double hours = 0.0; };
    svr.Get("/api/payroll/summary", [db](const httplib::Request& req, httplib::Response& res) {
        auto uid_str = req.get_param_value("userId");
        auto from = req.get_param_value("from"); // YYYY-MM-DD (UTC)
        auto to = req.get_param_value("to");
        if (uid_str.empty() || from.empty() || to.empty()) {
            res.status = 400; res.set_content(R"({"error":"userId, from, to required"})", "application/json"); return;
        }
        int user_id = std::stoi(uid_str);

        // Hourly rate
        double hourly = 0.0;
        {
            sqlite3_stmt* s = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT hourly_rate FROM users WHERE id=?", -1, &s, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(s, 1, user_id);
                if (sqlite3_step(s) == SQLITE_ROW) hourly = sqlite3_column_double(s, 0);
                sqlite3_finalize(s);
            }
        }

        // Fetch events in range
        const char* SQL =
            "SELECT type, ts_utc FROM events "
            "WHERE user_id=? AND substr(ts_utc,1,10)>=? AND substr(ts_utc,1,10)<=? "
            "ORDER BY ts_utc ASC;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
            res.status = 500; res.set_content(R"({"error":"query failed"})", "application/json"); return;
        }
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, from.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, to.c_str(), -1, SQLITE_TRANSIENT);

        std::map<std::string, DaySummary> days;
        bool in_session = false, in_break = false;
        time_t t_in = 0, t_break_start = 0;
        std::string cur_day;

        auto close_day_if_open = [&](const std::string& d) {
            // For MVP, drop open tails
            in_session = false; in_break = false; t_in = 0; t_break_start = 0;
            };

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string ts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string day = ts.substr(0, 10);
            time_t t = parse_iso_utc(ts);

            if (cur_day.empty()) cur_day = day;
            if (day != cur_day) { close_day_if_open(cur_day); cur_day = day; }

            if (type == "IN") {
                if (!in_session) { in_session = true; t_in = t; }
            }
            else if (type == "BREAK_START") {
                if (in_session && !in_break) { in_break = true; t_break_start = t; }
            }
            else if (type == "BREAK_END") {
                if (in_session && in_break) {
                    t_in += (t - t_break_start);
                    in_break = false; t_break_start = 0;
                }
            }
            else if (type == "OUT") {
                if (in_session) {
                    if (in_break) { t_in += (t - t_break_start); in_break = false; t_break_start = 0; }
                    double hours = double(t - t_in) / 3600.0;
                    days[day].hours += std::max(0.0, hours);
                    in_session = false; t_in = 0;
                }
            }
        }
        sqlite3_finalize(stmt);

        // Build result
        double total_hours = 0.0;
        json drows = json::array();
        for (auto& kv : days) {
            total_hours += kv.second.hours;
            drows.push_back({ {"date",kv.first},{"hours",kv.second.hours},{"pay", kv.second.hours * hourly} });
        }
        json out = {
          {"userId", user_id},
          {"hourly_rate", hourly},
          {"total_hours", total_hours},
          {"total_pay", total_hours * hourly},
          {"days", drows}
        };
        res.set_content(out.dump(), "application/json");
        });

    // 4) Start server
    std::cout << "Starting server on http://127.0.0.1:8080 (GET /health)\n";
    if (!svr.bind_to_port("0.0.0.0", 8080)) {
        std::cerr << "ERROR: bind_to_port failed (port busy or firewall)\n";
        running.store(false);
        if (ui.joinable()) ui.join();
        sqlite3_close(db);
        return 1;
    }
    std::cout << "Bind OK, listening...\n";
    svr.listen_after_bind(); // blocks until quit

    // 5) Shutdown
    running.store(false);
    if (ui.joinable()) ui.join();
    sqlite3_close(db);
    return 0;
}
