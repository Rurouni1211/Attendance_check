#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

struct User {
    int         id;
    std::string name;
    double      rate;
    std::string api_token; // NEW: per-user token for mobile
};

std::vector<User> load_users(sqlite3* db);
int insert_user(sqlite3* db, const std::string& name, double rate, std::string* out_err = nullptr);

bool update_user(sqlite3* db, int id, const std::string& name, double rate);
bool delete_user(sqlite3* db, int id);

// Lookup by token (used by HTTP when mobile sends userToken)
bool find_user_id_by_token(sqlite3* db, const std::string& token, int& out_user_id);
