(module
    (global $g (mut i32) (i32.const 10))
    ;; Increases $g by $delta and returns the new value.
    (func (export "call") (result i32)
        (global.set $g
            (i32.add
                (global.get $g)
                (i32.const 20)
            )
        )
        (global.get $g)
    )
)