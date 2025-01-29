  (func (export "main") (result i32)
      (block (result i32)
          (drop
              (br_if 0
                  (i32.const 6)
                  (br_table 0 0
                      (i32.const 9)
                      (i32.const 0)
                  )
              )
          )
          (i32.const 7)
      )
  )