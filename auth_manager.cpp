#include "auth_manager.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

static std::string sha256_hex(const std::string& s) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), h);
    std::ostringstream o; o << std::hex << std::setfill('0');
    for (unsigned char b : h) o << std::setw(2) << (int)b;
    return o.str();
}

bool ensure_admins_table(sqlite3* db) {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS admins("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT UNIQUE NOT NULL,"
        " password_hash TEXT NOT NULL);";
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) { sqlite3_free(err); return false; }
    return true;
}

bool any_admin_exists(sqlite3* db) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM admins LIMIT 1;", -1, &st, nullptr) != SQLITE_OK) return false;
    bool exists = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return exists;
}

bool create_admin(sqlite3* db, const std::string& user, const std::string& pass_plain) {
    std::string ph = sha256_hex(pass_plain);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "INSERT INTO admins(username,password_hash) VALUES(?,?);", -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ph.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    return ok;
}

bool verify_admin(sqlite3* db, const std::string& user, const std::string& pass_plain) {
    std::string ph = sha256_hex(pass_plain);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT id FROM admins WHERE username=? AND password_hash=?;", -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ph.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return ok;
}
