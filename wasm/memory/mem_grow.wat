(module
  (memory 1 2) ;; start with one memory page, and max of 2 pages
  (func (export "call") (result i32)

    ;; grow memory by 1 page
    ;; grow returns in 1 for success and -1 for failure
    ;; will fail if you change to more more than 1 page
    (memory.grow (i32.const 1))
    i32.const 1
    i32.eq
  )
)