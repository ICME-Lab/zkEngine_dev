(module
    (global $global_i32 i32 (i32.const 0))
    (global $global_i64 i64 (i64.const 0))

    (func (export "call")
        (global.get $global_i32)
        (drop)
        (global.get $global_i64)
        (drop)
    )
)