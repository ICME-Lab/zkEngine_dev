(module
  (memory 2) ;; start with one memory page, and max of 2 pages
  (func (export "main") (result i32)
    memory.size 
    i32.const 1
    i32.eq
  )
)