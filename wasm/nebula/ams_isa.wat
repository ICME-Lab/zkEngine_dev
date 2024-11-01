    (module
        (func (export "main") (result i64)
            i64.const 1000
            i64.const 42
            i64.const 42
            i64.const 100
            i64.add
            i64.mul
            i64.add
        )
    )