(module
    (func (export "my_func") (result i32)
		i32.const 100
      	i32.const 42
        i32.add
      	i32.const 100
        i32.add
      	i32.const 42
        i32.mul
    )
)