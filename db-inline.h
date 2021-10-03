#pragma once

#include <sqlite3.h>

static int sqlite3_lasterrno;

static inline intptr_t kk_sqlite3_open(kk_string_t filename, kk_db__open_mode mode, kk_context_t *ctx) {
  sqlite3 *ret;
  sqlite3_lasterrno = sqlite3_open_v2(
    kk_string_cbuf_borrow(filename, NULL),
    &ret,
    (mode.write ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY) |
      (mode.create ? SQLITE_OPEN_CREATE : 0) |
      (mode.uri ? SQLITE_OPEN_URI : 0) |
      (mode.memory ? SQLITE_OPEN_MEMORY : 0),
    NULL
  );
  return (intptr_t)ret;
}

static inline intptr_t kk_sqlite3_prepare(intptr_t raw, kk_string_t sql, kk_context_t *ctx) {
  sqlite3 *db = (sqlite3*) raw;
  sqlite3_stmt *ret;
  kk_ssize_t len;

  char const *sqlstr = kk_string_cbuf_borrow(sql, &len);
  sqlite3_lasterrno = sqlite3_prepare_v2(db, sqlstr, len, &ret, NULL);
  return (intptr_t) ret;
}

static inline kk_string_t kk_sqlite3_column_text(intptr_t raw, int32_t idx, kk_context_t *ctx) {
  sqlite3_stmt *stmt = (sqlite3_stmt *) raw;
  char const *ret = (char const *) sqlite3_column_text(stmt, idx);
  kk_ssize_t len = (kk_ssize_t) sqlite3_column_bytes(stmt, idx);
  return kk_string_alloc_from_qutf8n(len, ret, ctx);
}

static inline kk_string_t kk_sqlite3_exec(intptr_t raw, kk_string_t sql, kk_context_t *ctx) {
  sqlite3 *db = (sqlite3*) raw;
  char *errmsg = NULL;
  sqlite3_lasterrno = sqlite3_exec(db, kk_string_cbuf_borrow(sql, NULL), NULL, NULL, &errmsg);
  if (errmsg != NULL) {
    kk_string_t ret = kk_string_alloc_from_qutf8(errmsg, ctx);
    sqlite3_free(errmsg);
    return ret;
  } else {
    return kk_string_empty();
  }
}

static inline int kk_sqlite3_bind_string(intptr_t raw, int32_t idx, kk_string_t value, kk_context_t *ctx) {
  sqlite3_stmt *stmt = (sqlite3_stmt *) raw;
  kk_ssize_t len;
  char const *str = kk_string_cbuf_borrow(value, &len);
  return sqlite3_bind_text64(stmt, idx, str, len, SQLITE_TRANSIENT, SQLITE_UTF8);
}
