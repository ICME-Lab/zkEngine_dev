(module
    (func (export "main") (result i32)
		    i64.const 1000
            i64.const 42
            i64.const 42
            i64.const 100
            i64.add
            i64.sub
            i64.mul
            i64.const 1000
            i64.div_u
            i64.const 1000
            i64.rem_u
            i64.clz
            i64.eqz
    )
)