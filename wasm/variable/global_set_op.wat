  (module
      (global $global_i32 (mut i32) (i32.const 10))
      (global $global_i64 (mut i64) (i64.const 10))

      (func (export "call")
          (i32.const 0)
          (global.set $global_i32)
          (i64.const 0)
          (global.set $global_i64)
      )
  )