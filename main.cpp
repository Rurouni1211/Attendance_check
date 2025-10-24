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

using nlohmann::json;
using namespace std;
namespace fs = std::filesystem;

// ---- QR timing & UI ----
static constexpr long SLOT_SECONDS = 120;        // each QR valid for 120s
static constexpr int  WINDOW_W = 1000;           // window width
static constexpr int  WINDOW_H = 720;            // window height
static constexpr int  ALLOWED_SLOT_DRIFT = 1;    // accept current slot ±1

// ----- JST helpers (UTC+9) -----
static constexpr int JST_OFFSET_SECS = 9 * 3600;

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

static inline std::string iso_from_time_t_with_offset(time_t t, int offset_secs, const char* offset_label) {
    t += offset_secs;
    std::tm lm{};
#if defined(_WIN32)
    gmtime_s(&lm, &t);
#else
    lm = *std::gmtime(&t);
#endif
    return iso_from_tm(lm, offset_label);
}

// Now in JST (ISO8601 with +09:00 suffix)
static inline std::string iso_now_jst() {
    time_t now = std::time(nullptr);
    return iso_from_time_t_with_offset(now, JST_OFFSET_SECS, "+09:00");
}

// ===================== General helpers =====================
static int exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) { std::cerr << "SQL error: " << (err ? err : "") << "\n"; sqlite3_free(err); }
    return rc;
}

static inline std::string iso_now_utc() {
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

// Convert an ISO UTC "YYYY-MM-DDTHH:MM:SSZ" to a nice JST display "YYYY-MM-DD HH:MM:SS JST"
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

// Compute JST day window -> returned as UTC ISO strings
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

// Compute today's JST window in UTC ISO strings
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

static inline bool is_leap(int y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}
static inline int days_in_month(int y, int m) {
    static const int dm[] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
    return (m == 2) ? (dm[m - 1] + (is_leap(y) ? 1 : 0)) : dm[m - 1];
}

// ===================== QR / HMAC config =====================
static const std::string OFFICE_ID = "HQ-1";                         // change for your site
static const std::string OFFICE_SECRET = "change-me-please-32byte-min";  // strong secret!

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

// Current SLOT_SECONDS slot + signed JSON payload
static inline QrBundle make_qr_payload() {
    long now = std::time(nullptr);
    long slot = now / SLOT_SECONDS;
    std::string nonce = rand_hex(8);
    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce;
    std::string sig = hmac_sha256_hex(OFFICE_SECRET, data);
    json j{ {"ver",1},{"office_id",OFFICE_ID},{"slot",slot},{"nonce",nonce},{"sig",sig} };
    return { j.dump(), slot, nonce };
}

// ===================== libqrencode → draw in ImGui =====================
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
    dl->AddRectFilled(p0, ImVec2(p0.x + sizePx, p0.y + sizePx), IM_COL32(255, 255, 255, 255)); // bg

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

static inline std::vector<User> load_users(sqlite3* db) {
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

static inline bool insert_event(sqlite3* db, int user_id, const std::string& type, const std::string& device = "gui") {
    std::string ts_utc = iso_now_utc();
    std::string ts_local = iso_now_jst();
    const char* SQL = "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ts_utc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, device.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

// compute work/break hours in a given UTC time window (strings)
struct TodayStats { double work_hours = 0.0; double break_hours = 0.0; };

static inline TodayStats compute_window(sqlite3* db, int user_id, const std::string& start_utc_iso, const std::string& end_utc_iso) {
    const char* SQL =
        "SELECT type, ts_utc FROM events "
        "WHERE user_id=? AND ts_utc >= ? AND ts_utc < ? "
        "ORDER BY ts_utc ASC;";
    sqlite3_stmt* s = nullptr;
    TodayStats out{};
    if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return out;

    sqlite3_bind_int(s, 1, user_id);
    sqlite3_bind_text(s, 2, start_utc_iso.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, end_utc_iso.c_str(), -1, SQLITE_TRANSIENT);

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
                t_in += (t - t_break_start);
                in_break = false; t_break_start = 0;
            }
        }
        else if (type == "OUT") {
            if (in_session) {
                if (in_break) {
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

static inline TodayStats compute_today(sqlite3* db, int user_id) {
    std::string start_utc_iso, end_utc_iso;
    jst_today_utc_window(start_utc_iso, end_utc_iso);
    return compute_window(db, user_id, start_utc_iso, end_utc_iso);
}

// ---------- load events helper (time range) ----------
static inline std::vector<json> load_events_in_range(sqlite3* db, int user_id, const std::string& start_utc_iso, const std::string& end_utc_iso) {
    std::vector<json> rows;
    const char* SQL =
        "SELECT e.id, e.user_id, u.name, e.type, e.ts_utc, e.ts_local, e.device_id "
        "FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "WHERE e.user_id = ? AND e.ts_utc >= ? AND e.ts_utc < ? "
        "ORDER BY e.id ASC;";
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return rows;
    sqlite3_bind_int(s, 1, user_id);
    sqlite3_bind_text(s, 2, start_utc_iso.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, end_utc_iso.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        json r;
        r["id"] = sqlite3_column_int64(s, 0);
        r["userId"] = sqlite3_column_int(s, 1);
        r["name"] = (sqlite3_column_type(s, 2) != SQLITE_NULL) ? (const char*)sqlite3_column_text(s, 2) : "";
        r["type"] = (const char*)sqlite3_column_text(s, 3);
        r["ts_utc"] = (const char*)sqlite3_column_text(s, 4);
        if (sqlite3_column_type(s, 5) != SQLITE_NULL) r["ts_local"] = (const char*)sqlite3_column_text(s, 5);
        if (sqlite3_column_type(s, 6) != SQLITE_NULL) r["device_id"] = (const char*)sqlite3_column_text(s, 6);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return rows;
}

// ---------- Recent events (simple feed) ----------
static inline std::vector<json> load_recent(sqlite3* db, int limit = 12, int only_user_id = -1) {
    std::vector<json> rows;
    const char* SQL_ALL =
        "SELECT e.id, e.user_id, u.name, e.type, e.ts_utc, e.ts_local, e.device_id "
        "FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "ORDER BY e.id DESC LIMIT ?;";
    const char* SQL_USER =
        "SELECT e.id, e.user_id, u.name, e.type, e.ts_utc, e.ts_local, e.device_id "
        "FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "WHERE e.user_id = ? ORDER BY e.id DESC LIMIT ?;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, only_user_id > 0 ? SQL_USER : SQL_ALL, -1, &s, nullptr) != SQLITE_OK) {
        return rows;
    }
    int idx = 1;
    if (only_user_id > 0) sqlite3_bind_int(s, idx++, only_user_id);
    sqlite3_bind_int(s, idx, limit);

    while (sqlite3_step(s) == SQLITE_ROW) {
        json r;
        r["id"] = sqlite3_column_int64(s, 0);
        r["userId"] = sqlite3_column_int(s, 1);
        r["name"] = (sqlite3_column_type(s, 2) != SQLITE_NULL) ? (const char*)sqlite3_column_text(s, 2) : "";
        r["type"] = (const char*)sqlite3_column_text(s, 3);
        r["ts_utc"] = (const char*)sqlite3_column_text(s, 4);
        if (sqlite3_column_type(s, 5) != SQLITE_NULL) r["ts_local"] = (const char*)sqlite3_column_text(s, 5);
        if (sqlite3_column_type(s, 6) != SQLITE_NULL) r["device_id"] = (const char*)sqlite3_column_text(s, 6);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return rows;
}

// ---------- QR verify + anti-replay ----------
struct VerifyResult { bool ok = false; std::string error; };
static inline VerifyResult verify_qr_and_mark(sqlite3* db, const json& qr) {
    if (!qr.contains("ver") || !qr.contains("office_id") || !qr.contains("slot")
        || !qr.contains("nonce") || !qr.contains("sig")) {
        return { false, "QR missing fields" };
    }
    if (qr["office_id"].get<std::string>() != OFFICE_ID) {
        return { false, "QR office mismatch" };
    }
    long slot = qr["slot"].get<long>();
    std::string nonce = qr["nonce"].get<std::string>();
    std::string sig = qr["sig"].get<std::string>();

    long now_slot = std::time(nullptr) / SLOT_SECONDS;
    if (std::llabs(now_slot - slot) > ALLOWED_SLOT_DRIFT) {
        return { false, "QR expired/too old" };
    }

    std::string data = OFFICE_ID + "|" + std::to_string(slot) + "|" + nonce;
    std::string expect = hmac_sha256_hex(OFFICE_SECRET, data);
    auto eq_ci = [](char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); };
    if (!std::equal(expect.begin(), expect.end(), sig.begin(), sig.end(), eq_ci)) {
        return { false, "QR signature invalid" };
    }

    const char* SQL = "INSERT INTO used_nonces(office_id,slot,nonce) VALUES(?,?,?);";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, nullptr) != SQLITE_OK) {
        return { false, "DB prepare failed" };
    }
    sqlite3_bind_text(st, 1, OFFICE_ID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)slot);
    sqlite3_bind_text(st, 3, nonce.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        return { false, "QR already used" };
    }
    return { true, "" };
}

// Delete the last `limit` events (by id DESC). Returns #rows deleted.
static inline int clear_recent_events(sqlite3* db, int limit = 20) {
    const char* SQL =
        "DELETE FROM events WHERE id IN ("
        "  SELECT id FROM events ORDER BY id DESC LIMIT ?"
        ");";
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return 0;
    sqlite3_bind_int(s, 1, limit);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return 0;
    return sqlite3_changes(db);
}

// ===================== Export helpers =====================

// Format YYYY-MM-DD (JST today)
static inline std::string jst_today_date_str() {
    time_t t = std::time(nullptr) + JST_OFFSET_SECS;
    std::tm j{};
#if defined(_WIN32)
    gmtime_s(&j, &t);
#else
    j = *std::gmtime(&t);
#endif
    char buf[16]; std::strftime(buf, sizeof(buf), "%Y-%m-%d", &j);
    return buf;
}

// Export daily report for given JST date
static inline void export_daily_report(sqlite3* db, int user_id, const std::string& user_name, double rate, int year, int month, int day) {
    fs::create_directories("records");
    char dbuf[16]; std::snprintf(dbuf, sizeof(dbuf), "%04d-%02d-%02d", year, month, day);
    std::string base = std::string("records/") + dbuf;

    std::ofstream txt(base + ".txt");
    std::ofstream csv(base + ".csv");
    if (!txt || !csv) {
        std::cerr << "Failed to open daily report files.\n";
        return;
    }

    std::string start_utc_iso, end_utc_iso;
    jst_day_window(year, month, day, start_utc_iso, end_utc_iso);

    auto rows = load_events_in_range(db, user_id, start_utc_iso, end_utc_iso);

    txt << "Daily Report (" << dbuf << " JST) - " << user_name << "\n";
    txt << "---------------------------------------------\n";
    csv << "id,user,type,ts_jst\n";

    for (auto& r : rows) {
        std::string tsj = ts_utc_to_jst_display(r["ts_utc"].get<std::string>());
        txt << "#" << r["id"].get<long long>() << "  " << user_name << "  " << r["type"].get<std::string>()
            << "  " << tsj << "\n";
        csv << r["id"].get<long long>() << "," << user_name << "," << r["type"].get<std::string>() << "," << tsj << "\n";
    }

    TodayStats s = compute_window(db, user_id, start_utc_iso, end_utc_iso);
    double money = s.work_hours * rate;

    txt << "\nSummary:\n";
    txt << "Work:  " << s.work_hours << " h\n";
    txt << "Break: " << s.break_hours << " h\n";
    txt << "Money: " << money << " yen\n";

    csv << "\nSummary,,, \n";
    csv << "total_work,total_break,total_money\n";
    csv << s.work_hours << "," << s.break_hours << "," << money << "\n";

    std::cout << "Saved daily TXT/CSV: " << base << ".txt/.csv\n";
}

// Export monthly salary CSV for a given month (YYYY, MM)
static inline void export_monthly_salary(sqlite3* db, int user_id, const std::string& user_name, double rate, int year, int month) {
    fs::create_directories("monthly_reports");
    char mbuf[32]; std::snprintf(mbuf, sizeof(mbuf), "%04d-%02d", year, month);
    std::string path = std::string("monthly_reports/") + user_name + "-" + mbuf + "-salary.csv";

    std::ofstream f(path);
    if (!f) { std::cerr << "Failed to open " << path << "\n"; return; }

    f << "date,work_hours,break_hours,money\n";
    int dim = days_in_month(year, month);

    double sum_work = 0.0, sum_break = 0.0, sum_money = 0.0;

    for (int d = 1; d <= dim; ++d) {
        std::string start_utc_iso, end_utc_iso;
        jst_day_window(year, month, d, start_utc_iso, end_utc_iso);
        TodayStats s = compute_window(db, user_id, start_utc_iso, end_utc_iso);
        double money = s.work_hours * rate;
        sum_work += s.work_hours;
        sum_break += s.break_hours;
        sum_money += money;

        char datebuf[16]; std::snprintf(datebuf, sizeof(datebuf), "%04d-%02d-%02d", year, month, d);
        f << datebuf << "," << s.work_hours << "," << s.break_hours << "," << money << "\n";
    }
    f << "TOTAL," << sum_work << "," << sum_break << "," << sum_money << "\n";

    std::cout << "Saved monthly CSV: " << path << "\n";
}

// ===================== HTTP server (separate DB connection) =====================
static void run_server(std::atomic<bool>& server_ok) {
    try {
        sqlite3* sdb = nullptr;
        if (sqlite3_open("attendance.db", &sdb) != SQLITE_OK) {
            std::cerr << "HTTP thread DB open failed\n";
            server_ok.store(false);
            return;
        }
        exec_sql(sdb, "PRAGMA journal_mode=WAL;");

        httplib::Server svr;

        auto add_cors = [](httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Headers", "Content-Type");
            res.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            };

        // OPTIONS preflight for any path
        svr.Options(R"(.*)", [add_cors](const httplib::Request&, httplib::Response& res) {
            add_cors(res);
            res.status = 204;
            });

        svr.set_logger([](const auto& req, const auto& res) {
            std::cout << req.method << " " << req.path << " -> " << res.status << "\n";
            });

        svr.Get("/health", [add_cors](const httplib::Request&, httplib::Response& res) {
            add_cors(res);
            res.set_content("{\"ok\":true}", "application/json");
            });

        // expose current QR payload (for mobile dev)
        svr.Get("/api/qr/current", [add_cors](const httplib::Request&, httplib::Response& res) {
            add_cors(res);
            auto qb = make_qr_payload();
            res.set_content(qb.json, "application/json");
            });

        // simple reads
        svr.Get("/api/events/recent", [sdb, add_cors](const httplib::Request&, httplib::Response& res) {
            add_cors(res);
            const char* SQL = "SELECT id,user_id,type,ts_utc,ts_local,device_id FROM events ORDER BY id DESC LIMIT 20;";
            sqlite3_stmt* stmt = nullptr; json out = json::array();
            if (sqlite3_prepare_v2(sdb, SQL, -1, &stmt, nullptr) == SQLITE_OK) {
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

        // POST /api/events
        svr.Post("/api/events", [sdb, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            try {
                std::string ct = req.get_header_value("Content-Type");
                std::string ct2 = req.get_header_value("content-type");
                if (ct.find("application/json") == std::string::npos && ct2.find("application/json") == std::string::npos) {
                    res.status = 400; res.set_content(R"({"error":"Content-Type must be application/json"})", "application/json"); return;
                }
                json body = json::parse(req.body);

                if (!body.contains("userId") || !body["userId"].is_number_integer()) {
                    res.status = 400; res.set_content(R"({"error":"userId (integer) is required"})", "application/json"); return;
                }
                if (!body.contains("type") || !body["type"].is_string()) {
                    res.status = 400; res.set_content(R"({"error":"type (string) is required"})", "application/json"); return;
                }
                if (!body.contains("qr") || !body["qr"].is_object()) {
                    res.status = 400; res.set_content(R"({"error":"qr object is required"})", "application/json"); return;
                }
                auto vr = verify_qr_and_mark(sdb, body["qr"]);
                if (!vr.ok) {
                    json err = { {"error","QR invalid"}, {"detail", vr.error} };
                    res.status = 400; res.set_content(err.dump(), "application/json"); return;
                }

                const int user_id = body["userId"].get<int>();
                const std::string type = body["type"].get<std::string>();
                static const std::unordered_set<std::string> kAllowed{ "IN","OUT","BREAK_START","BREAK_END" };
                if (!kAllowed.count(type)) {
                    res.status = 400; res.set_content(R"({"error":"type must be IN|OUT|BREAK_START|BREAK_END"})", "application/json"); return;
                }

                std::string ts_utc = iso_now_utc();
                std::string ts_local = iso_now_jst();
                std::string device_id = body.value("deviceId", "");

                const char* SQL = "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(sdb, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
                    res.status = 500; res.set_content(R"({"error":"prepare failed"})", "application/json"); return;
                }
                sqlite3_bind_int(stmt, 1, user_id);
                sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, ts_utc.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT);
                if (!device_id.empty()) sqlite3_bind_text(stmt, 5, device_id.c_str(), -1, SQLITE_TRANSIENT);
                else sqlite3_bind_null(stmt, 5);

                bool ok = sqlite3_step(stmt) == SQLITE_DONE;
                sqlite3_finalize(stmt);
                if (!ok) { res.status = 500; res.set_content(R"({"error":"insert failed"})", "application/json"); return; }

                json out = { {"ok",true},{"userId",user_id},{"type",type},{"ts_utc",ts_utc} };
                res.set_content(out.dump(), "application/json");
            }
            catch (const std::exception& e) {
                json err = { {"error","invalid JSON"}, {"detail", e.what()} };
                res.status = 400; res.set_content(err.dump(), "application/json");
            }
            });

        if (!svr.bind_to_port("0.0.0.0", 8080)) {
            std::cerr << "HTTP bind failed\n";
            server_ok.store(false);
            sqlite3_close(sdb);
            return;
        }
        server_ok.store(true);
        svr.listen_after_bind();
        sqlite3_close(sdb);
    }
    catch (...) { server_ok.store(false); }
}

// ===================== main =====================
int main() {
    // DB bootstrap (GUI thread connection)
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

    // Start HTTP server in background (with its own DB connection)
    std::atomic<bool> http_ok{ false };
    std::thread http_thread(run_server, std::ref(http_ok));

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

    // recent clear state
    static int clearLimit = 20;

    // monthly picker (default to JST current month)
    char monthBuf[8] = { 0 }; // "YYYY-MM"
    {
        time_t t = std::time(nullptr) + JST_OFFSET_SECS;
        std::tm j{};
#if defined(_WIN32)
        gmtime_s(&j, &t);
#else
        j = *std::gmtime(&t);
#endif
        std::snprintf(monthBuf, sizeof(monthBuf), "%04d-%02d", j.tm_year + 1900, j.tm_mon + 1);
    }

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
                    ImGui::Text("Selected user id: %d", users[selected_user_idx].id);
                    ImGui::Text("Hourly rate: %.2f yen/h", users[selected_user_idx].rate);
                }
            }
        }

        // Today stats + controls
        if (ImGui::CollapsingHeader("Today (JST)", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (selected_user_idx >= 0) {
                auto stats = compute_today(db, users[selected_user_idx].id);
                ImGui::Text("Working: %.2f h", stats.work_hours);
                ImGui::Text("Break:   %.2f h", stats.break_hours);
                ImGui::Text("Estimated pay (today): %.0f yen", stats.work_hours * users[selected_user_idx].rate);
                ImGui::Separator();

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

                // Export buttons
                if (ImGui::Button("Generate Daily Report (JST today)")) {
                    // today JST
                    time_t t = std::time(nullptr) + JST_OFFSET_SECS;
                    std::tm j{};
#if defined(_WIN32)
                    gmtime_s(&j, &t);
#else
                    j = *std::gmtime(&t);
#endif
                    export_daily_report(db, users[selected_user_idx].id, users[selected_user_idx].name, users[selected_user_idx].rate,
                        j.tm_year + 1900, j.tm_mon + 1, j.tm_mday);
                }
                ImGui::SameLine();
                ImGui::SetNextItemWidth(100);
                ImGui::InputText("Month (YYYY-MM)", monthBuf, IM_ARRAYSIZE(monthBuf));
                ImGui::SameLine();
                if (ImGui::Button("Generate Monthly Salary CSV")) {
                    // parse YYYY-MM
                    int y = 0, m = 0;
                    if (std::sscanf(monthBuf, "%d-%d", &y, &m) == 2 && y >= 1970 && m >= 1 && m <= 12) {
                        export_monthly_salary(db, users[selected_user_idx].id, users[selected_user_idx].name, users[selected_user_idx].rate, y, m);
                    }
                    else {
                        std::cerr << "Invalid month format. Use YYYY-MM.\n";
                    }
                }
            }
            else {
                ImGui::Text("Select a user above.");
            }
        }

        // Recent events (live feed) + clear buttons
        if (ImGui::CollapsingHeader("Recent events", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::SetNextItemWidth(100);
            ImGui::InputInt("Clear limit", &clearLimit);
            if (clearLimit < 1) clearLimit = 1;

            ImGui::SameLine();
            if (ImGui::Button("Clear last N")) {
                int removed = clear_recent_events(db, clearLimit);
                std::cout << "Removed last " << removed << " events\n";
            }

            ImGui::SameLine();
            if (ImGui::Button("Clear ALL")) {
                exec_sql(db, "DELETE FROM events;");
                int removed = sqlite3_changes(db);
                std::cout << "Removed ALL events: " << removed << "\n";
            }

            ImGui::Separator();

            auto recents = load_recent(db, 12 /*limit*/);
            ImGui::BeginChild("recent_events", ImVec2(0, 180), true);
            for (auto& r : recents) {
                ImGui::Text("#%lld  %-12s  user:%d (%s)  ts:%s",
                    (long long)r["id"].get<long long>(),
                    r["type"].get<std::string>().c_str(),
                    r["userId"].get<int>(),
                    r["name"].get<std::string>().c_str(),
                    ts_utc_to_jst_display(r["ts_utc"].get<std::string>()).c_str()
                );
            }
            ImGui::EndChild();
        }

        // QR panel with "Reload QR now"
        if (ImGui::CollapsingHeader("QR (scan in-office)", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Text("Office: %s", OFFICE_ID.c_str());
            ImGui::Text("Slot seconds: %ld", SLOT_SECONDS);

            if (ImGui::Button("Reload QR now")) {
                qrBundle = make_qr_payload();               // new nonce/signature
                qrPix = make_qr_pixels(qrBundle.json);   // redraw
                lastSlot = std::time(nullptr) / SLOT_SECONDS;
            }

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

    // Auto-export today's report for selected user on exit (optional)
    if (selected_user_idx >= 0) {
        time_t t = std::time(nullptr) + JST_OFFSET_SECS;
        std::tm j{};
#if defined(_WIN32)
        gmtime_s(&j, &t);
#else
        j = *std::gmtime(&t);
#endif
        export_daily_report(db, users[selected_user_idx].id, users[selected_user_idx].name, users[selected_user_idx].rate,
            j.tm_year + 1900, j.tm_mon + 1, j.tm_mday);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();

    if (http_thread.joinable()) http_thread.detach();
    sqlite3_close(db);
    return 0;
}
