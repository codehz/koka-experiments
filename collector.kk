effect collector<a>
  ctl emit(value: a) : ()

val collect-list = handler
  return (x) []
  ctl emit(v) Cons(v, resume(()))
