effect collector<a>
  ctl emit(value: a) : ()

fun collect-list(action)
  val f = handle(action)
    return (x) fn() []
    ctl emit(v) fn() Cons(v, resume(())())
  f()
