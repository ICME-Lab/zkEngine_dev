(module
  (memory (export "memory") 1)
  (func $run (result i32)
    i32.const 0
    i32.const 42
    i32.store

    i32.const 0
    i32.load
  )
  (export "run" (func $run))
)