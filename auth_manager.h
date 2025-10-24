#pragma once
#include <string>
#include <sqlite3.h>

bool ensure_admins_table(sqlite3* db);
bool any_admin_exists(sqlite3* db);
bool create_admin(sqlite3* db, const std::string& user, const std::string& pass_plain);
bool verify_admin(sqlite3* db, const std::string& user, const std::string& pass_plain);
