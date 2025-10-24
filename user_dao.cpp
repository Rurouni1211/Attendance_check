#include "user_dao.h"
#include <random>
#include <sstream>
#include <iomanip>

static std::string gen_token(size_t nbytes = 16) {
    std::random_device rd; std::mt19937_64 g(rd());
    std::uniform_int_distribution<unsigned> d(0, 255);
    std::ostringstream o; o << std::hex << std::setfill('0');
    for (size_t i = 0; i < nbytes; ++i) o << std::setw(2) << d(g);
    return o.str();
}

std::vector<User> load_users(sqlite3* db) {
    std::vector<User> v; sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db,
        "SELECT id,name,hourly_rate,COALESCE(api_token,'') FROM users ORDER BY id ASC",
        -1, &s, nullptr) == SQLITE_OK) {
        while (sqlite3_step(s) == SQLITE_ROW) {
            v.push_back(User{
                sqlite3_column_int(s,0),
                reinterpret_cast<const char*>(sqlite3_column_text(s,1)),
                sqlite3_column_double(s,2),
                reinterpret_cast<const char*>(sqlite3_column_text(s,3))
                });
        }
        sqlite3_finalize(s);
    }
    return v;
}

int insert_user(sqlite3* db, const std::string& name, double rate, std::string* out_err) {
    auto gen_token = []() {
        std::random_device rd; std::mt19937_64 g(rd());
        std::uniform_int_distribution<unsigned> d(0, 255);
        std::ostringstream o; o << std::hex << std::setfill('0');
        for (int i = 0; i < 16; i++) o << std::setw(2) << d(g);
        return o.str();
        };

    const char* SQL = "INSERT INTO users(name,hourly_rate,api_token) VALUES(?,?,?);";
    for (int attempt = 0; attempt < 5; ++attempt) {
        std::string tok = gen_token();
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db, SQL, -1, &s, nullptr) != SQLITE_OK) {
            if (out_err) *out_err = sqlite3_errmsg(db);
            return -1;
        }
        sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(s, 2, rate);
        sqlite3_bind_text(s, 3, tok.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(s);
        sqlite3_finalize(s);

        if (rc == SQLITE_DONE) {
            return (int)sqlite3_last_insert_rowid(db);
        }
        // If UNIQUE constraint on api_token, retry with a new token
        if (rc == SQLITE_CONSTRAINT) {
            const char* msg = sqlite3_errmsg(db);
            if (msg && std::string(msg).find("idx_users_api_token") != std::string::npos) {
                continue; // retry token
            }
        }
        if (out_err) *out_err = sqlite3_errmsg(db);
        return -1;
    }
    if (out_err) *out_err = "Failed after multiple token attempts.";
    return -1;
}

bool update_user(sqlite3* db, int id, const std::string& name, double rate) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "UPDATE users SET name=?, hourly_rate=? WHERE id=?;", -1, &s, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(s, 2, rate);
    sqlite3_bind_int(s, 3, id);
    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s); return ok && sqlite3_changes(db) > 0;
}

bool delete_user(sqlite3* db, int id) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "DELETE FROM users WHERE id=?;", -1, &s, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(s, 1, id);
    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s); return ok && sqlite3_changes(db) > 0;
}

bool find_user_id_by_token(sqlite3* db, const std::string& token, int& out_user_id) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT id FROM users WHERE api_token=?;", -1, &s, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) == SQLITE_ROW) {
        out_user_id = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        return true;
    }
    sqlite3_finalize(s);
    return false;
}
