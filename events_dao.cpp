#include "events_dao.h"
#include <ctime>

static std::string iso_now_utc() {
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

static std::string iso_now_jst() {
    constexpr int JST_OFFSET = 9 * 3600;
    std::time_t t = std::time(nullptr) + JST_OFFSET;
    std::tm j{};
#if defined(_WIN32)
    gmtime_s(&j, &t);
#else
    j = *std::gmtime(&t);
#endif
    char buf[40];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &j);
    return std::string(buf) + "+09:00";
}

bool insert_event(sqlite3* db, int user_id, const std::string& type, const std::string& device) {
    static const char* SQL =
        "INSERT INTO events(user_id,type,ts_utc,ts_local,device_id) VALUES(?,?,?,?,?);";
    const std::string ts_utc = iso_now_utc();
    const std::string ts_local = iso_now_jst();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(s, 1, user_id);
    sqlite3_bind_text(s, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, ts_utc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, ts_local.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, device.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s);
    return ok;
}
