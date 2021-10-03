extern import
  c { vcpkg="sqlite3"; library="sqlite3" }

extern import
  c file "db-inline.h"

type db-noexn :: X
alias db = <db-noexn,exn>

type open-mode
  OpenMode
    write  : bool = True
    create : bool = True
    uri    : bool = False
    memory : bool = False

private extern c-lasterror() : db-noexn int32
  c inline "sqlite3_lasterrno"

private extern c-errstr(errcode : int32) : db-noexn string
  c inline "kk_string_alloc_dup_valid_utf8(sqlite3_errstr(#1), kk_context())"

private extern c-errmsg(db : intptr_t) : db-noexn string
  c inline "kk_string_alloc_dup_valid_utf8(sqlite3_errmsg((sqlite3*)#1), kk_context())"

private extern c-close(db : intptr_t) : db-noexn ()
  c inline "sqlite3_close((sqlite3*)#1)"

private extern c-open(filename : string, mode : open-mode) : db-noexn intptr_t
  c "kk_sqlite3_open"

private extern c-changes(db : intptr_t) : db-noexn int32
  c inline "sqlite3_changes((sqlite3*)#1)"

private extern c-last-insert-rowid(db : intptr_t) : db-noexn int64
  c inline "sqlite3_last_insert_rowid((sqlite3*)#1)"

private extern c-exec(db : intptr_t, sql : string) : db-noexn string
  c "kk_sqlite3_exec"

private extern c-prepare(db : intptr_t, sql : string) : db-noexn intptr_t
  c "kk_sqlite3_prepare"

private extern c-finalize(stmt : intptr_t) : db-noexn int32
  c inline "sqlite3_finalize((sqlite3_stmt*)#1)"

private extern c-step(stmt : intptr_t) : db-noexn int32
  c inline "sqlite3_step((sqlite3_stmt*)#1)"

private extern c-reset(stmt : intptr_t) : db-noexn int32
  c inline "sqlite3_reset((sqlite3_stmt*)#1)"

private extern c-column-int(stmt : intptr_t, idx : int32) : db-noexn int64
  c inline "sqlite3_column_int64((sqlite3_stmt*)#1, #2)"

private extern c-column-double(stmt : intptr_t, idx : int32) : db-noexn double
  c inline "sqlite3_column_double((sqlite3_stmt*)#1, #2)"

private extern c-column-string(stmt : intptr_t, idx : int32) : db-noexn string
  c "kk_sqlite3_column_text"

private extern c-bind-null(stmt : intptr_t, idx : int32) : db-noexn int32
  c inline "sqlite3_bind_null((sqlite3_stmt*)#1, #2)"

private extern c-bind-int(stmt : intptr_t, idx : int32, value : int64) : db-noexn int32
  c inline "sqlite3_bind_int64((sqlite3_stmt*)#1, #2, #3)"

private extern c-bind-double(stmt : intptr_t, idx : int32, value : double) : db-noexn int32
  c inline "sqlite3_bind_double((sqlite3_stmt*)#1, #2, #3)"

private extern c-bind-string(stmt : intptr_t, idx : int32, value : string) : db-noexn int32
  c "kk_sqlite3_bind_string"

private inline fun db-error(errcode : int32 = c-lasterror())
  Exception(c-errstr(errcode), ExnInternal("SQLite3"))
private inline fun db-error(db : intptr_t)
  Exception(c-errmsg(db), ExnInternal("SQLite3"))

private inline fun throw-db-error(src : int32 = c-lasterror())
  throw-exn(db-error(src))
private inline fun throw-db-error(src : intptr_t)
  throw-exn(db-error(src))
  
private fun check-ret(ret : int32) : db ()
  if ret.int != 0 then
    throw-db-error(ret)

private fun open(filename : string, mode : open-mode = OpenMode()) : db intptr_t
  val ret = c-open(filename, mode)
  if int(ret) != 0 then
    ret
  else
    throw-db-error()

scoped effect db-instance<s::S>
  val db-instance : intptr_t
alias db-context<s::S> = <db-instance<s>,db>

named effect statement<s::S> in db-instance<s>
  fun statement() : intptr_t

scoped effect statement-view<s::S>
  val statement-view : intptr_t

inline fun unsafe-db-context(raw : intptr_t, action : forall<s::S> () -> <db-context<s>|e> a) : <db|e> a
  handle(action)
    val db-instance = raw

fun sqlite3(filename : string, action : forall<s::S> () -> <db-context<s>|e> a) : <db|e> a
  val db = open(filename)
  with finally { db.c-close() }
  unsafe-db-context(db, action)

fun sqlite3(filename : string, mode : open-mode, action : forall<s::S> () -> <db-context<s>|e> a) : <db|e> a
  val db = open(filename, mode)
  with finally { db.c-close() }
  unsafe-db-context(db, action)

inline fun changes() : db-context<s> int
  c-changes(db-instance).int

inline fun last-insert-rowid() : db-context<s> int
  c-last-insert-rowid(db-instance).int

fun prepare(sql : string) : db-context<s> statement<s>
  val stmt = db-instance.c-prepare(sql)
  if int(stmt) == 0 then
    throw-db-error(db-instance)
  with ret = named handler fun statement() stmt
  ret

fun exec(sql : string) : db-context<s> ()
  val ret = db-instance.c-exec(sql)
  if ret.is-notempty then
    throw(ret)

fun exec(stmt : statement<s>) : <db-context<s>,div> ()
  with finally
    stmt.statement.c-reset().check-ret
  val ret = c-step(stmt.statement)
  match ret.int
    101 -> ()
    100 -> throw("try exec query statement")
    _   -> throw-db-error(ret)

fun [](stmt : statement<s>, idx : int, value : ()) : <db-context<s>,div> ()
  stmt.statement.c-bind-null(idx.int32).check-ret

fun [](stmt : statement<s>, idx : int, value : int) : <db-context<s>,div> ()
  stmt.statement.c-bind-int(idx.int32, value.int64).check-ret

fun [](stmt : statement<s>, idx : int, value : double) : <db-context<s>,div> ()
  stmt.statement.c-bind-double(idx.int32, value).check-ret

fun [](stmt : statement<s>, idx : int, value : string) : <db-context<s>,div> ()
  stmt.statement.c-bind-string(idx.int32, value).check-ret

fun foreach(
  stmt   : statement<s>,
  action : forall<r::S> () -> <db-context<s>,statement-view<r>,div|e> a
) : <db-context<s>,div|e> ()
  with finally
    stmt.statement.c-reset().check-ret
  fun rep()
    val ret = c-step(stmt.statement)
    match ret.int
      100 ->
        handle(action) val statement-view = stmt.statement
        rep()
      101 -> ()
      _   -> throw-db-error(ret)
  rep()

fun column-int(idx : int)    : <statement-view<s>,db-noexn> int
  statement-view.c-column-int(idx.int32).int

fun column-double(idx : int) : <statement-view<s>,db-noexn> double
  statement-view.c-column-double(idx.int32)

fun column-string(idx : int) : <statement-view<s>,db-noexn> string
  statement-view.c-column-string(idx.int32)
