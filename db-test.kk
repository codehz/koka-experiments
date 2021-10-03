import db

fun main()
  with sqlite3("test.db")
  exec("create table if not exists mydb(key TEXT, value INT)")
  val stmt = prepare("select ?, ?")
  stmt[1] := 5
  stmt[2] := "test"
  stmt.foreach
    println("here " ++ column-int(0).show ++ " " ++ column-string(1))
  try {
    prepare("wrong")
    ()
  } fn (e) {
    println("cought: " ++ e.show)
  }
  ()
