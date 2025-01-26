(module
    (func (export "main") (result i32)
		    i32.const 1000
            i32.const 42
            i32.const 42
            i32.const 100
            i32.add
            i32.sub
            i32.mul
            i32.const 1000
            i32.div_u
            i32.const 1000
            i32.rem_u
            i32.clz
            i32.eqz
    )
)