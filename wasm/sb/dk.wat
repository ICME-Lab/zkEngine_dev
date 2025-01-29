(module
    (type (;0;) (func (result i64)))
    (type (;1;) (func (param i64 i64) (result i64)))
    (func (type 0) (result i64)
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
            i64.const 100
            call 1
            i64.const 1000
            i64.add
    )
    (func (type 1) (param i64) (param i64) (result i64)
    local.get 0
    local.get 1
    drop
    )
    (export "main" (func 0))
)