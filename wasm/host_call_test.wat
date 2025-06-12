 (module
   (import "host" "call" (func $f (param i32) (result i32)))
   (memory 1 2)
   (func $test
    (i32.const 42)
    (call $f)
    (drop)
   )
   (export "test" (func $test))
 )
