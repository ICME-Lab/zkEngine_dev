(module
  (memory (export "memory") 1)
  (func $main (result i64)
    i32.const 0
    i64.const 42
    i64.store

    i32.const 0
    i64.load
  )
  (export "main" (func $main))
)