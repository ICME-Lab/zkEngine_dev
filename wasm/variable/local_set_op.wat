  (module
      (func (export "call")
          (local i32 i64)
          (i32.const 10)
          (local.set 0)
          (i64.const 100)
          (local.set 1)
          (local.get 0)
          drop
          (local.get 1)
          drop
      )
  )