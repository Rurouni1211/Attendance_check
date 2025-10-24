// main.cpp
#define SDL_MAIN_HANDLED
#include <httplib.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <qrencode.h>
#include <SDL.h>
#include <SDL_opengl.h>

#include <imgui.h>
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"

#include <iostream>
#include <fstream>
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
#include <cctype>
#include <filesystem>
#include <cstdio>

#include "user_dao.h"
#include "events_dao.h"

using nlohmann::json;
namespace fs = std::filesystem;

// ---- QR timing & UI ----
static constexpr long SLOT_SECONDS = 120;
static constexpr int  WINDOW_W = 1000;
static constexpr int  WINDOW_H = 720;
static constexpr int  ALLOWED_SLOT_DRIFT = 1;

// ----- JST helpers -----
static constexpr int JST_OFFSET_SECS = 9 * 3600;

static bool users_has_column(sqlite3* db, const char* col) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(users);", -1, &st, nullptr) != SQLITE_OK) return false;
    bool found = false;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        if (name && std::string(name) == col) { found = true; break; }
    }
    sqlite3_finalize(st);
    return found;
}

static void migrate_users_table(sqlite3* db) {
    char* err = nullptr;
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS users("
        " id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " hourly_rate REAL DEFAULT 0"
        ");", nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    if (!users_has_column(db, "api_token")) {
        sqlite3_exec(db, "ALTER TABLE users ADD COLUMN api_token TEXT;", nullptr, nullptr, &err);
        if (err) { sqlite3_free(err); err = nullptr; }
    }
    sqlite3_exec(db,
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_token ON users(api_token);",
        nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }
}

static inline std::string iso_from_tm(const std::tm& tm, const char* suffix) {
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return std::string(buf) + (suffix ? suffix : "");
}
static inline std::string iso_from_time_t_utc(time_t t) {
    std::tm g{};
#if defined(_WIN32)
    gmtime_s(&g, &t);
#else
    g = *std::gmtime(&t);
#endif
    return iso_from_tm(g, "Z");
}
static inline std::string iso_from_time_t_with_offset(time_t t, int offset_secs, const char* label) {
    t += offset_secs;
    std::tm lm{};
#if defined(_WIN32)
    gmtime_s(&lm, &t);
#else
    lm = *std::gmtime(&t);
#endif
    return iso_from_tm(lm, label);
}
static inline std::string iso_now_utc() {
    std::time_t t = std::time(nullptr);
    std::tm g{};
#if defined(_WIN32)
    gmtime_s(&g, &t);
#else
    g = *std::gmtime(&t);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &g);
    return buf;
}
static inline time_t parse_iso_utc(const std::string& s) {
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
static inline std::string iso_now_jst() {
    time_t now = std::time(nullptr);
    return iso_from_time_t_with_offset(now, JST_OFFSET_SECS, "+09:00");
}
static inline std::string ts_utc_to_jst_display(const std::string& ts_utc) {
    time_t t = parse_iso_utc(ts_utc);
    t += JST_OFFSET_SECS;
    std::tm j{};
#if defined(_WIN32)
    gmtime_s(&j, &t);
#else
    j = *std::gmtime(&t);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &j);
    return std::string(buf) + " JST";
}
static inline void jst_day_window(int year, int month, int day, std::string& start_utc_iso, std::string& end_utc_iso) {
    std::tm j{};
    j.tm_year = year - 1900;
    j.tm_mon = month - 1;
    j.tm_mday = day;
    j.tm_hour = 0; j.tm_min = 0; j.tm_sec = 0;
#if defined(_WIN32)
    time_t jst_midnight = _mkgmtime(&j);
#else
    time_t jst_midnight = timegm(&j);
#endif
    time_t utc_start = jst_midnight - JST_OFFSET_SECS;
    time_t utc_end = utc_start + 24 * 3600;
    start_utc_iso = iso_from_time_t_utc(utc_start);
    end_utc_iso = iso_from_time_t_utc(utc_end);
}
static inline void jst_today_utc_window(std::string& start_utc_iso, std::string& end_utc_iso) {
    time_t now = std::time(nullptr);
    time_t jst_now = now + JST_OFFSET_SECS;
    std::tm j{};
#if defined(_WIN32)
    gmtime_s(&j, &jst_now);
#else
    j = *std::gmtime(&jst_now);
#endif
    int y = j.tm_year + 1900, m = j.tm_mon + 1, d = j.tm_mday;
    jst_day_window(y, m, d, start_utc_iso, end_utc_iso);
}
static inline bool is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }
static inline int days_in_month(int y, int m) {
    static const int dm[] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
    return (m == 2) ? (dm[m - 1] + (is_leap(y) ? 1 : 0)) : dm[m - 1];
}

// ===================== QR / HMAC =====================
static const std::string OFFICE_ID = "HQ-1";
static const std::string OFFICE_SECRET = "change-me-please-32byte-min";

static inline std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        mac, &len);
    std::ostringstream oss; oss << std::hex << std::setfill('0');
    for (unsigned i = 0; i < len; i++) oss << std::setw(2) << (int)mac[i];
    return oss.str();
}
static inline std::string rand_hex(size_t nbytes = 8) {
    std::random_device rd; std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned> dist(0, 255);
    std::ostringstream oss; oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < nbytes; i++) oss << std::setw(2) << dist(gen);
    return oss.str();
}
struct QrBundle { std::string json; long slot; std::string nonce; };
static inline QrBundle make_qr_payload() {
    long now = std::time(nullptr);
    long slot = now / SLOT_SECONDS;
    std::string nonce = rand_hex(8);
    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce;
    std::string sig = hmac_sha256_hex(OFFICE_SECRET, data);
    json j{ {"ver",1},{"office_id",OFFICE_ID},{"slot",slot},{"nonce",nonce},{"sig",sig} };
    return { j.dump(), slot, nonce };
}

// QR drawing
struct QrPixels { int modules = 0, quiet = 4; std::vector<uint8_t> bits; };
static inline QrPixels make_qr_pixels(const std::string& text, int quiet = 4) {
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
static inline void imgui_draw_qr(const QrPixels& q, float sizePx) {
    if (q.modules <= 0) return;
    int total = q.modules + 2 * q.quiet;
    float scale = sizePx / (float)total;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    dl->AddRectFilled(p0, ImVec2(p0.x + sizePx, p0.y + sizePx), IM_COL32(255, 255, 255, 255));
    for (int y = 0; y < q.modules; ++y)
        for (int x = 0; x < q.modules; ++x)
            if (q.bits[y * q.modules + x]) {
                float rx = (x + q.quiet) * scale, ry = (y + q.quiet) * scale;
                dl->AddRectFilled(ImVec2(p0.x + rx, p0.y + ry), ImVec2(p0.x + rx + scale, p0.y + ry + scale), IM_COL32(0, 0, 0, 255));
            }
    ImGui::Dummy(ImVec2(sizePx, sizePx));
}

// ===================== Event helpers (overnight-safe) =====================

// round seconds to nearest minute, then to hours
static inline double seconds_to_hours_rounded_minute(long long seconds) {
    long long minutes = (seconds + 30) / 60; // nearest minute
    return minutes / 60.0;
}

struct TodayStats {
    long long work_secs = 0;
    long long break_secs = 0;
    double work_hours()  const { return seconds_to_hours_rounded_minute(work_secs); }
    double break_hours() const { return seconds_to_hours_rounded_minute(break_secs); }
};

// simulate events across [start, end), carrying state across midnight
static inline TodayStats compute_window(sqlite3* db, int user_id, const std::string& start_utc_iso, const std::string& end_utc_iso) {
    TodayStats out{};
    const time_t WSTART = parse_iso_utc(start_utc_iso);
    const time_t WEND = parse_iso_utc(end_utc_iso);

    // ---- 1) Seed state with all events BEFORE window start
    const char* SQL_BEFORE =
        "SELECT type, ts_utc FROM events "
        "WHERE user_id=? AND ts_utc < ? "
        "ORDER BY ts_utc ASC;";
    sqlite3_stmt* sb = nullptr;
    if (sqlite3_prepare_v2(db, SQL_BEFORE, -1, &sb, nullptr) != SQLITE_OK) return out;
    sqlite3_bind_int(sb, 1, user_id);
    sqlite3_bind_text(sb, 2, start_utc_iso.c_str(), -1, SQLITE_TRANSIENT);

    bool in_session = false, in_break = false;
    time_t t_in = 0, t_break_start = 0;

    while (sqlite3_step(sb) == SQLITE_ROW) {
        std::string type = reinterpret_cast<const char*>(sqlite3_column_text(sb, 0));
        time_t t = parse_iso_utc(reinterpret_cast<const char*>(sqlite3_column_text(sb, 1)));

        if (type == "IN") {
            if (!in_session) { in_session = true; t_in = t; }
        }
        else if (type == "BREAK_START") {
            if (in_session && !in_break) { in_break = true; t_break_start = t; }
        }
        else if (type == "BREAK_END") {
            if (in_session && in_break) {
                if (t > t_break_start) {
                    out.break_secs += (t - t_break_start);
                    t_in += (t - t_break_start);
                }
                in_break = false; t_break_start = 0;
            }
        }
        else if (type == "OUT") {
            if (in_session) {
                if (in_break) {
                    if (t > t_break_start) {
                        out.break_secs += (t - t_break_start);
                        t_in += (t - t_break_start);
                    }
                    in_break = false; t_break_start = 0;
                }
                if (t > t_in) out.work_secs += (t - t_in);
                in_session = false; t_in = 0;
            }
        }
    }
    sqlite3_finalize(sb);

    // carry state at WSTART
    if (in_session) {
        t_in = std::max(t_in, WSTART);
        if (in_break) t_break_start = std::max(t_break_start, WSTART);
    }

    // ---- 2) Process events inside [WSTART, WEND)
    const char* SQL_IN =
        "SELECT type, ts_utc FROM events "
        "WHERE user_id=? AND ts_utc >= ? AND ts_utc < ? "
        "ORDER BY ts_utc ASC;";
    sqlite3_stmt* si = nullptr;
    if (sqlite3_prepare_v2(db, SQL_IN, -1, &si, nullptr) != SQLITE_OK) return out;
    sqlite3_bind_int(si, 1, user_id);
    sqlite3_bind_text(si, 2, start_utc_iso.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(si, 3, end_utc_iso.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(si) == SQLITE_ROW) {
        std::string type = reinterpret_cast<const char*>(sqlite3_column_text(si, 0));
        time_t t = parse_iso_utc(reinterpret_cast<const char*>(sqlite3_column_text(si, 1)));
        if (t > WEND) t = WEND;

        if (type == "IN") {
            if (!in_session) { in_session = true; t_in = t; }
        }
        else if (type == "BREAK_START") {
            if (in_session && !in_break) { in_break = true; t_break_start = t; }
        }
        else if (type == "BREAK_END") {
            if (in_session && in_break) {
                if (t > t_break_start) {
                    out.break_secs += (t - t_break_start);
                    t_in += (t - t_break_start);
                }
                in_break = false; t_break_start = 0;
            }
        }
        else if (type == "OUT") {
            if (in_session) {
                if (in_break) {
                    if (t > t_break_start) {
                        out.break_secs += (t - t_break_start);
                        t_in += (t - t_break_start);
                    }
                    in_break = false; t_break_start = 0;
                }
                if (t > t_in) out.work_secs += (t - t_in);
                in_session = false; t_in = 0;
            }
        }
    }
    sqlite3_finalize(si);

    // ---- 3) Close any spans crossing WEND
    if (in_session) {
        if (in_break) {
            if (WEND > t_break_start) {
                out.break_secs += (WEND - t_break_start);
                t_in += (WEND - t_break_start);
            }
            in_break = false; t_break_start = 0;
        }
        if (WEND > t_in) out.work_secs += (WEND - t_in);
        in_session = false; t_in = 0;
    }

    return out;
}

static inline TodayStats compute_today(sqlite3* db, int user_id) {
    std::string s, e; jst_today_utc_window(s, e); return compute_window(db, user_id, s, e);
}

static inline std::vector<json> load_events_in_range(sqlite3* db, int user_id, const std::string& s, const std::string& e) {
    std::vector<json> rows; sqlite3_stmt* st = nullptr;
    const char* SQL =
        "SELECT e.id, e.user_id, u.name, e.type, e.ts_utc, e.ts_local, e.device_id "
        "FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "WHERE e.user_id = ? AND e.ts_utc >= ? AND e.ts_utc < ? ORDER BY e.id ASC;";
    if (sqlite3_prepare_v2(db, SQL, -1, &st, nullptr) != SQLITE_OK) return rows;
    sqlite3_bind_int(st, 1, user_id); sqlite3_bind_text(st, 2, s.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 3, e.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        json r; r["id"] = sqlite3_column_int64(st, 0); r["userId"] = sqlite3_column_int(st, 1);
        r["name"] = (sqlite3_column_type(st, 2) != SQLITE_NULL) ? (const char*)sqlite3_column_text(st, 2) : "";
        r["type"] = (const char*)sqlite3_column_text(st, 3); r["ts_utc"] = (const char*)sqlite3_column_text(st, 4);
        if (sqlite3_column_type(st, 5) != SQLITE_NULL) r["ts_local"] = (const char*)sqlite3_column_text(st, 5);
        if (sqlite3_column_type(st, 6) != SQLITE_NULL) r["device_id"] = (const char*)sqlite3_column_text(st, 6);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(st); return rows;
}

static inline std::vector<json> load_recent(sqlite3* db, int limit = 12) {
    std::vector<json> rows; sqlite3_stmt* st = nullptr;
    const char* SQL =
        "SELECT e.id, e.user_id, u.name, e.type, e.ts_utc, e.ts_local, e.device_id "
        "FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "ORDER BY e.id DESC LIMIT ?;";
    if (sqlite3_prepare_v2(db, SQL, -1, &st, nullptr) != SQLITE_OK) return rows;
    sqlite3_bind_int(st, 1, limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        json r; r["id"] = sqlite3_column_int64(st, 0); r["userId"] = sqlite3_column_int(st, 1);
        r["name"] = (sqlite3_column_type(st, 2) != SQLITE_NULL) ? (const char*)sqlite3_column_text(st, 2) : "";
        r["type"] = (const char*)sqlite3_column_text(st, 3); r["ts_utc"] = (const char*)sqlite3_column_text(st, 4);
        if (sqlite3_column_type(st, 5) != SQLITE_NULL) r["ts_local"] = (const char*)sqlite3_column_text(st, 5);
        if (sqlite3_column_type(st, 6) != SQLITE_NULL) r["device_id"] = (const char*)sqlite3_column_text(st, 6);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(st); return rows;
}

// Anti-replay
struct VerifyResult { bool ok = false; std::string error; };
static inline VerifyResult verify_qr_and_mark(sqlite3* db, const json& qr) {
    if (!qr.contains("ver") || !qr.contains("office_id") || !qr.contains("slot") || !qr.contains("nonce") || !qr.contains("sig"))
        return { false,"QR missing fields" };
    if (qr["office_id"].get<std::string>() != OFFICE_ID) return { false,"QR office mismatch" };
    long slot = qr["slot"].get<long>(); std::string nonce = qr["nonce"].get<std::string>(); std::string sig = qr["sig"].get<std::string>();
    long now_slot = std::time(nullptr) / SLOT_SECONDS; if (std::llabs(now_slot - slot) > ALLOWED_SLOT_DRIFT) return { false,"QR expired/too old" };
    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce; std::string expect = hmac_sha256_hex(OFFICE_SECRET, data);
    auto eq_ci = [](char a, char b) {return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); };
    if (!std::equal(expect.begin(), expect.end(), sig.begin(), sig.end(), eq_ci)) return { false,"QR signature invalid" };
    const char* SQL = "INSERT INTO used_nonces(office_id,slot,nonce) VALUES(?,?,?);";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, nullptr) != SQLITE_OK) return { false,"DB prepare failed" };
    sqlite3_bind_text(st, 1, OFFICE_ID.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 2, (sqlite3_int64)slot); sqlite3_bind_text(st, 3, nonce.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st); sqlite3_finalize(st); if (rc != SQLITE_DONE) return { false,"QR already used" }; return { true,"" };
}
static inline int clear_recent_events(sqlite3* db, int limit = 20) {
    const char* SQL = "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id DESC LIMIT ?);";
    sqlite3_stmt* s = nullptr; if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return 0;
    sqlite3_bind_int(s, 1, limit); int rc = sqlite3_step(s); sqlite3_finalize(s); if (rc != SQLITE_DONE) return 0; return sqlite3_changes(db);
}

// ===================== Export helpers =====================
static inline void export_daily_report(sqlite3* db, int user_id, const std::string& user_name, double rate, int year, int month, int day) {
    fs::create_directories("records");
    char dbuf[16]; std::snprintf(dbuf, sizeof(dbuf), "%04d-%02d-%02d", year, month, day);
    std::string base = std::string("records/") + dbuf;

    std::ofstream txt(base + ".txt");
    std::ofstream csv(base + ".csv");
    if (!txt || !csv) { std::cerr << "Failed to open daily report files.\n"; return; }

    std::string s, e; jst_day_window(year, month, day, s, e);
    auto rows = load_events_in_range(db, user_id, s, e);

    txt << "Daily Report (" << dbuf << " JST) - " << user_name << "\n";
    txt << "---------------------------------------------\n";
    csv << "id,user,type,ts_jst\n";
    for (auto& r : rows) {
        std::string tsj = ts_utc_to_jst_display(r["ts_utc"].get<std::string>());
        txt << "#" << r["id"].get<long long>() << "  " << user_name << "  " << r["type"].get<std::string>() << "  " << tsj << "\n";
        csv << r["id"].get<long long>() << "," << user_name << "," << r["type"].get<std::string>() << "," << tsj << "\n";
    }

    TodayStats st = compute_window(db, user_id, s, e);
    double money = st.work_hours() * rate;

    txt << "\nSummary:\n";
    txt << "Work:  " << st.work_hours() << " h\n";
    txt << "Break: " << st.break_hours() << " h\n";
    txt << "Money: " << money << " yen\n";

    csv << "\nSummary,,,\n";
    csv << "total_work,total_break,total_money\n";
    csv << st.work_hours() << "," << st.break_hours() << "," << money << "\n";

    std::cout << "Saved daily TXT/CSV: " << base << ".txt/.csv\n";
}

static inline void export_monthly_salary(sqlite3* db, int user_id, const std::string& name, double rate, int y, int m) {
    fs::create_directories("monthly_reports");
    char mbuf[32]; std::snprintf(mbuf, sizeof(mbuf), "%04d-%02d", y, m);
    std::string path = std::string("monthly_reports/") + name + "-" + mbuf + "-salary.csv";
    std::ofstream f(path); if (!f) { std::cerr << "Failed to open " << path << "\n"; return; }
    f << "date,work_hours,break_hours,money\n";
    int dim = days_in_month(y, m);
    double sw = 0, sb = 0, sm = 0;
    for (int d = 1; d <= dim; ++d) {
        std::string s, e; jst_day_window(y, m, d, s, e);
        TodayStats st = compute_window(db, user_id, s, e);
        double money = st.work_hours() * rate;
        sw += st.work_hours(); sb += st.break_hours(); sm += money;
        char datebuf[16]; std::snprintf(datebuf, sizeof(datebuf), "%04d-%02d-%02d", y, m, d);
        f << datebuf << "," << st.work_hours() << "," << st.break_hours() << "," << money << "\n";
    }
    f << "TOTAL," << sw << "," << sb << "," << sm << "\n";
    std::cout << "Saved monthly CSV: " << path << "\n";
}

// ===================== HTTP server (separate DB connection) =====================
static void run_server(std::atomic<bool>& server_ok) {
    try {
        sqlite3* sdb = nullptr;
        if (sqlite3_open("attendance.db", &sdb) != SQLITE_OK) { std::cerr << "HTTP thread DB open failed\n"; server_ok.store(false); return; }

        auto exec_sql = [](sqlite3* db, const char* sql) { char* err = nullptr; int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err); if (rc != SQLITE_OK && err) { sqlite3_free(err); } return rc; };
        exec_sql(sdb, "PRAGMA journal_mode=WAL;");

        httplib::Server svr;
        auto add_cors = [](httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Headers", "Content-Type");
            res.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            };
        svr.Options(R"(.*)", [add_cors](const httplib::Request&, httplib::Response& res) { add_cors(res); res.status = 204; });
        svr.set_logger([](const auto& req, const auto& res) { std::cout << req.method << " " << req.path << " -> " << res.status << "\n"; });

        svr.Get("/health", [add_cors](const httplib::Request&, httplib::Response& res) { add_cors(res); res.set_content("{\"ok\":true}", "application/json"); });
        svr.Get("/api/qr/current", [add_cors](const httplib::Request&, httplib::Response& res) { add_cors(res); auto qb = make_qr_payload(); res.set_content(qb.json, "application/json"); });

        // Recent feed
        svr.Get("/api/events/recent", [sdb, add_cors](const httplib::Request&, httplib::Response& res) {
            add_cors(res);
            const char* SQL = "SELECT id,user_id,type,ts_utc,ts_local,device_id FROM events ORDER BY id DESC LIMIT 20;";
            sqlite3_stmt* stmt = nullptr; json out = json::array();
            if (sqlite3_prepare_v2(sdb, SQL, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    json row; row["id"] = sqlite3_column_int64(stmt, 0); row["userId"] = sqlite3_column_int(stmt, 1);
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

        // Event ingest: prefers userToken, falls back to userId
        svr.Post("/api/events", [sdb, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            try {
                std::string ct = req.get_header_value("Content-Type"), ct2 = req.get_header_value("content-type");
                if (ct.find("application/json") == std::string::npos && ct2.find("application/json") == std::string::npos) {
                    res.status = 400; res.set_content(R"({"error":"Content-Type must be application/json"})", "application/json"); return;
                }
                json body = json::parse(req.body);

                // resolve user by token (preferred) or id
                int user_id = -1;
                if (body.contains("userToken") && body["userToken"].is_string()) {
                    std::string tok = body["userToken"].get<std::string>();
                    sqlite3_stmt* st = nullptr;
                    if (sqlite3_prepare_v2(sdb, "SELECT id FROM users WHERE api_token=?;", -1, &st, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(st, 1, tok.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(st) == SQLITE_ROW) user_id = sqlite3_column_int(st, 0);
                        sqlite3_finalize(st);
                    }
                    if (user_id <= 0) { res.status = 400; res.set_content(R"({"error":"invalid userToken"})", "application/json"); return; }
                }
                else if (body.contains("userId") && body["userId"].is_number_integer()) {
                    user_id = body["userId"].get<int>();
                }
                else {
                    res.status = 400; res.set_content(R"({"error":"userToken (preferred) or userId is required"})", "application/json"); return;
                }

                if (!body.contains("type") || !body["type"].is_string()) {
                    res.status = 400; res.set_content(R"({"error":"type (string) is required"})", "application/json"); return;
                }
                if (!body.contains("qr") || !body["qr"].is_object()) {
                    res.status = 400; res.set_content(R"({"error":"qr object is required"})", "application/json"); return;
                }

                auto vr = verify_qr_and_mark(sdb, body["qr"]);
                if (!vr.ok) { json err = { {"error","QR invalid"},{"detail",vr.error} }; res.status = 400; res.set_content(err.dump(), "application/json"); return; }

                const std::string type = body["type"].get<std::string>();
                static const std::unordered_set<std::string> kAllowed{ "IN","OUT","BREAK_START","BREAK_END" };
                if (!kAllowed.count(type)) { res.status = 400; res.set_content(R"({"error":"type must be IN|OUT|BREAK_START|BREAK_END"})", "application/json"); return; }

                std::string ts_utc = iso_now_utc(), ts_local = iso_now_jst();
                std::string device_id = body.value("deviceId", "");

                const char* SQL = "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(sdb, SQL, -1, &stmt, nullptr) != SQLITE_OK) { res.status = 500; res.set_content(R"({"error":"prepare failed"})", "application/json"); return; }
                sqlite3_bind_int(stmt, 1, user_id);
                sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, ts_utc.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT);
                if (!device_id.empty()) sqlite3_bind_text(stmt, 5, device_id.c_str(), -1, SQLITE_TRANSIENT); else sqlite3_bind_null(stmt, 5);

                bool ok = (sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt);
                if (!ok) { res.status = 500; res.set_content(R"({"error":"insert failed"})", "application/json"); return; }

                json out = { {"ok",true},{"userId",user_id},{"type",type},{"ts_utc",ts_utc} };
                res.set_content(out.dump(), "application/json");
            }
            catch (const std::exception& e) {
                json err = { {"error","invalid JSON"},{"detail",e.what()} }; res.status = 400; res.set_content(err.dump(), "application/json");
            }
            });

        if (!svr.bind_to_port("0.0.0.0", 8080)) { std::cerr << "HTTP bind failed\n"; server_ok.store(false); sqlite3_close(sdb); return; }
        server_ok.store(true);
        svr.listen_after_bind();
        sqlite3_close(sdb);
    }
    catch (...) { server_ok.store(false); }
}

// ===================== main =====================
int main() {
    // DB bootstrap + migration
    sqlite3* db = nullptr;
    if (sqlite3_open("attendance.db", &db) != SQLITE_OK) { std::cerr << "Failed to open DB\n"; return 1; }
    auto exec_sql = [&](const char* sql) { char* err = nullptr; int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err); if (rc != SQLITE_OK) { if (err) { std::cerr << "SQL: " << err << "\n"; sqlite3_free(err); } } return rc; };

    exec_sql("PRAGMA journal_mode=WAL;");
    exec_sql(
        "CREATE TABLE IF NOT EXISTS users("
        " id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " hourly_rate REAL DEFAULT 0,"
        " api_token TEXT UNIQUE);"
    );
    exec_sql(
        "CREATE TABLE IF NOT EXISTS events("
        " id INTEGER PRIMARY KEY,"
        " user_id INTEGER NOT NULL,"
        " type TEXT NOT NULL,"
        " ts_utc TEXT NOT NULL,"
        " ts_local TEXT,"
        " device_id TEXT);"
    );
    exec_sql(
        "CREATE TABLE IF NOT EXISTS used_nonces("
        " office_id TEXT NOT NULL,"
        " slot INTEGER NOT NULL,"
        " nonce TEXT NOT NULL,"
        " PRIMARY KEY(office_id,slot,nonce));"
    );
    migrate_users_table(db);

    // only message if empty
    sqlite3_stmt* chk = nullptr; int user_count = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM users;", -1, &chk, nullptr) == SQLITE_OK) {
        if (sqlite3_step(chk) == SQLITE_ROW) user_count = sqlite3_column_int(chk, 0);
        sqlite3_finalize(chk);
    }
    if (user_count == 0) std::cout << "No users present. Create one in the UI.\n";

    // HTTP server
    std::atomic<bool> http_ok{ false };
    std::thread http_thread(run_server, std::ref(http_ok));

    // GUI init
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO) != 0) { std::cerr << "SDL_Init: " << SDL_GetError() << "\n"; return 1; }
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_Window* window = SDL_CreateWindow("Attendance Console", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WINDOW_W, WINDOW_H, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    if (!window) { std::cerr << "SDL_CreateWindow failed\n"; return 1; }
    SDL_GLContext gl_ctx = SDL_GL_CreateContext(window); SDL_GL_MakeCurrent(window, gl_ctx); SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION(); ImGui::CreateContext(); ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark(); ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx); ImGui_ImplOpenGL3_Init("#version 130");

    // Users
    std::vector<User> users = load_users(db);
    int selected_user_idx = users.empty() ? -1 : 0;

    // Create user modal
    bool openCreateUserModal = users.empty();
    char newUserName[64] = "";
    double newUserRate = 1200.0;
    char createErr[128] = "";

    // Pairing QR state
    bool showPairingForSelected = false;
    QrPixels pairingQr{};

    // Office rotating QR
    auto qrBundle = make_qr_payload();
    auto qrPix = make_qr_pixels(qrBundle.json);
    long lastSlot = qrBundle.slot;

    // clearing
    int clearLimit = 20;

    // month picker
    char monthBuf[8] = { 0 }; // "YYYY-MM"
    { time_t t = std::time(nullptr) + JST_OFFSET_SECS; std::tm j{};
#if defined(_WIN32)
    gmtime_s(&j, &t);
#else
    j = *std::gmtime(&t);
#endif
    std::snprintf(monthBuf, sizeof(monthBuf), "%04d-%02d", j.tm_year + 1900, j.tm_mon + 1); }

    bool running = true;
    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) { ImGui_ImplSDL2_ProcessEvent(&e); if (e.type == SDL_QUIT) running = false; if (e.type == SDL_WINDOWEVENT && e.window.event == SDL_WINDOWEVENT_CLOSE && e.window.windowID == SDL_GetWindowID(window)) running = false; }

        long curSlot = std::time(nullptr) / SLOT_SECONDS;
        if (curSlot != lastSlot) { qrBundle = make_qr_payload(); qrPix = make_qr_pixels(qrBundle.json); lastSlot = curSlot; }

        ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplSDL2_NewFrame(); ImGui::NewFrame();

        ImGui::Begin("Attendance Console");
        ImGui::Text("Server: %s", http_ok.load() ? "listening on :8080" : "starting...");

        // Employees
        if (ImGui::CollapsingHeader("Employee", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (users.empty()) {
                ImGui::TextWrapped("No users found. Create your first user.");
                if (ImGui::Button("Create User…")) openCreateUserModal = true;
            }
            else {
                const char* current = users[selected_user_idx < 0 ? 0 : selected_user_idx].name.c_str();
                if (ImGui::BeginCombo("User", current)) {
                    for (int i = 0; i < (int)users.size(); ++i) { bool sel = (i == selected_user_idx); if (ImGui::Selectable(users[i].name.c_str(), sel)) selected_user_idx = i; if (sel) ImGui::SetItemDefaultFocus(); }
                    ImGui::EndCombo();
                }
                if (selected_user_idx >= 0) {
                    const auto& u = users[selected_user_idx];
                    ImGui::Text("ID: %d", u.id);
                    ImGui::Text("Hourly rate: %.2f yen/h", u.rate);
                    ImGui::TextWrapped("User token: %s", u.api_token.c_str());
                    if (ImGui::Button("Show Pair Mobile QR")) {
                        json pairing = { {"ver",1},{"office_id",OFFICE_ID},{"user_token",u.api_token} };
                        pairingQr = make_qr_pixels(pairing.dump());
                        showPairingForSelected = true;
                    }
                    if (showPairingForSelected) {
                        ImGui::Text("Pair this phone with user \"%s\"", u.name.c_str());
                        imgui_draw_qr(pairingQr, 240.f);
                        ImGui::TextWrapped("Scan once in the mobile app to save userToken. Then scan the rotating office QR to IN/OUT.");
                    }
                }
                if (ImGui::Button("Create User…")) openCreateUserModal = true;
                ImGui::SameLine();
                if (ImGui::Button("Delete Selected")) {
                    if (selected_user_idx >= 0) {
                        int delId = users[selected_user_idx].id;
                        if (delete_user(db, delId)) {
                            users = load_users(db);
                            selected_user_idx = users.empty() ? -1 : 0;
                            showPairingForSelected = false;
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Reload Users")) {
                    users = load_users(db);
                    if (selected_user_idx >= (int)users.size()) selected_user_idx = users.empty() ? -1 : 0;
                }
            }
        }

        // Create User modal
        if (openCreateUserModal) { ImGui::OpenPopup("Create User"); openCreateUserModal = false; }
        if (ImGui::BeginPopupModal("Create User", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::InputText("Name", newUserName, IM_ARRAYSIZE(newUserName));
            ImGui::InputDouble("Hourly rate (yen/h)", &newUserRate, 0.0, 0.0, "%.2f");
            if (createErr[0] != '\0') { ImGui::Spacing(); ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "%s", createErr); }
            ImGui::Spacing();
            if (ImGui::Button("Create")) {
                if (std::strlen(newUserName) == 0) std::snprintf(createErr, sizeof(createErr), "Name cannot be empty.");
                else if (newUserRate < 0.0)     std::snprintf(createErr, sizeof(createErr), "Rate must be >= 0.");
                else {
                    std::string err;
                    int newId = insert_user(db, newUserName, newUserRate); // events_dao.h not needed here
                    if (newId > 0) {
                        users = load_users(db);
                        selected_user_idx = 0; for (int i = 0; i < (int)users.size(); ++i) if (users[i].id == newId) { selected_user_idx = i; break; }
                        newUserName[0] = '\0'; newUserRate = 1200.0; createErr[0] = '\0'; showPairingForSelected = false;
                        ImGui::CloseCurrentPopup();
                    }
                    else {
                        std::snprintf(createErr, sizeof(createErr), "Create failed (duplicate name or DB error).");
                    }
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) { newUserName[0] = '\0'; newUserRate = 1200.0; createErr[0] = '\0'; ImGui::CloseCurrentPopup(); }
            ImGui::EndPopup();
        }

        // Today
        if (ImGui::CollapsingHeader("Today (JST)", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (selected_user_idx >= 0) {
                const auto& u = users[selected_user_idx];
                auto stats = compute_today(db, u.id);
                ImGui::Text("Working: %.2f h", stats.work_hours());
                ImGui::Text("Break:   %.2f h", stats.break_hours());
                ImGui::Text("Estimated pay (today): %.0f yen", stats.work_hours() * u.rate);
                ImGui::Separator();
                if (ImGui::Button("Check In")) { insert_event(db, u.id, "IN"); }
                ImGui::SameLine(); if (ImGui::Button("Break Start")) { insert_event(db, u.id, "BREAK_START"); }
                ImGui::SameLine(); if (ImGui::Button("Break End")) { insert_event(db, u.id, "BREAK_END"); }
                ImGui::SameLine(); if (ImGui::Button("Check Out")) { insert_event(db, u.id, "OUT"); }
            }
            else ImGui::Text("Select a user above.");
        }

        // Reports
        if (ImGui::CollapsingHeader("Reports", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (selected_user_idx >= 0) {
                const auto& u = users[selected_user_idx];
                if (ImGui::Button("Generate Daily Report (JST today)")) {
                    time_t t = std::time(nullptr) + JST_OFFSET_SECS; std::tm j{};
#if defined(_WIN32)
                    gmtime_s(&j, &t);
#else
                    j = *std::gmtime(&t);
#endif
                    export_daily_report(db, u.id, u.name, u.rate, j.tm_year + 1900, j.tm_mon + 1, j.tm_mday);
                }
                ImGui::SameLine(); ImGui::SetNextItemWidth(100);
                ImGui::InputText("Month (YYYY-MM)", monthBuf, IM_ARRAYSIZE(monthBuf));
                ImGui::SameLine();
                if (ImGui::Button("Generate Monthly Salary CSV")) {
                    int y = 0, m = 0;
                    if (std::sscanf(monthBuf, "%d-%d", &y, &m) == 2 && y >= 1970 && m >= 1 && m <= 12)
                        export_monthly_salary(db, u.id, u.name, u.rate, y, m);
                    else std::cerr << "Invalid month format. Use YYYY-MM.\n";
                }
            }
            else ImGui::Text("Select a user above.");
        }

        // Recent
        if (ImGui::CollapsingHeader("Recent events", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::SetNextItemWidth(100);
            ImGui::InputInt("Clear limit", &clearLimit); if (clearLimit < 1) clearLimit = 1;
            ImGui::SameLine(); if (ImGui::Button("Clear last N")) { int removed = clear_recent_events(db, clearLimit); std::cout << "Removed last " << removed << " events\n"; }
            ImGui::SameLine(); if (ImGui::Button("Clear ALL")) { char* err = nullptr; sqlite3_exec(db, "DELETE FROM events;", nullptr, nullptr, &err); if (err) { std::cerr << err << "\n"; sqlite3_free(err); } std::cout << "Removed ALL events.\n"; }
            ImGui::Separator();
            auto recents = load_recent(db);
            ImGui::BeginChild("recent_events", ImVec2(0, 180), true);
            for (auto& r : recents) {
                ImGui::Text("#%lld  %-12s  user:%d (%s)  ts:%s",
                    (long long)r["id"].get<long long>(),
                    r["type"].get<std::string>().c_str(),
                    r["userId"].get<int>(),
                    r["name"].get<std::string>().c_str(),
                    ts_utc_to_jst_display(r["ts_utc"].get<std::string>()).c_str());
            }
            ImGui::EndChild();
        }

        // QR (rotating office)
        if (ImGui::CollapsingHeader("QR (scan in-office)", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Text("Office: %s", OFFICE_ID.c_str());
            ImGui::Text("Slot seconds: %ld", SLOT_SECONDS);
            if (ImGui::Button("Reload QR now")) { auto qb = make_qr_payload(); qrBundle = qb; qrPix = make_qr_pixels(qb.json); lastSlot = std::time(nullptr) / SLOT_SECONDS; }
            ImGui::Text("Payload (debug):"); ImGui::BeginChild("qrpayload", ImVec2(0, 80), true); ImGui::TextWrapped("%s", qrBundle.json.c_str()); ImGui::EndChild();
            ImGui::Text("Code:"); imgui_draw_qr(qrPix, 260.0f);
        }

        ImGui::End();

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.08f, 0.08f, 0.08f, 1.0f); glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplSDL2_Shutdown(); ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx); SDL_DestroyWindow(window); SDL_Quit();
    if (http_thread.joinable()) http_thread.detach();
    sqlite3_close(db);
    return 0;
}
