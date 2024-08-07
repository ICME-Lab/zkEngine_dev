(module
    (func (export "call") (param i32) (param i32) (result i32)
        local.get 0
        local.get 1
        local.get 0
        local.get 1
        i32.add
        i32.add
        i32.mul
    )
)