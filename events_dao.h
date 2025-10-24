#pragma once
#include <string>
#include <sqlite3.h>

// Inserts an event with current UTC & JST timestamps.
// type Å∏ {"IN","OUT","BREAK_START","BREAK_END"}
bool insert_event(sqlite3* db, int user_id, const std::string& type, const std::string& device = "gui");
