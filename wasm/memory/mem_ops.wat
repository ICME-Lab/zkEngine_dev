(module

  (memory $memory 1)
  (export "memory" (memory $memory))

  (func (export "call")
    i32.const 4
    i32.const 100
    ;; store 100 at position 0
    i32.store

    i32.const 4
    i32.load
    drop
    i32.const 3
    i32.load
    drop
    i32.const 2
    i32.load
    drop
    i32.const 1
    i32.load
    drop
    i32.const 0
    i32.load
    drop

    i32.const 3
    i32.const 100
    ;; store 100 at position 0
    i32.store

    i32.const 4
    i32.load
    drop
    i32.const 3
    i32.load
    drop
    i32.const 2
    i32.load
    drop
    i32.const 1
    i32.load
    drop
    i32.const 0
    i32.load
    drop

    i32.const 4
    i32.const 0
    i32.store
    i32.const 3
    i32.const 0
    i32.store

    (i32.const 0)
    (i64.const 0)
    (i64.store offset=0)
    (i32.const 0)
    (i32.const 0)
    (i32.store offset=4)
    (i32.const 0)
    (i64.const 0x432134214)
    (i64.store offset=0)
    (i32.const 0)
    (i64.const 0)
    (i64.store32 offset=0)
    (i32.const 0)
    (i64.const 0)
    (i64.store16 offset=0)
    (i32.const 0)
    (i64.const 0)
    (i64.store8 offset=0)

    (i32.const 0)
    (i32.const 0)
    (i32.store offset=0)
    (i32.const 4)
    (i32.const 0)
    (i32.store offset=0)
    (i32.const 0)
    (i32.const 0)
    (i32.store16 offset=0)
    (i32.const 0)
    (i32.const 0)
    (i32.store8 offset=0)
    (i32.const 0)
    (i32.const 256)
    (i32.store8 offset=0)

    (i32.const 0)
    (i64.load offset=0)
    (drop)
    (i32.const 4)
    (i64.load offset=4)
    (drop)
    (i32.const 0)
    (i64.load32_u offset=0)
    (drop)
    (i32.const 0)
    (i64.load32_s offset=0)
    (drop)
    (i32.const 0)
    (i64.load16_u offset=0)
    (drop)
    (i32.const 0)
    (i64.load16_s offset=0)
    (drop)
    (i32.const 0)
    (i64.load8_u offset=0)
    (drop)
    (i32.const 0)
    (i64.load8_s offset=0)
    (drop)

    (i32.const 0)
    (i32.load offset=0)
    (drop)
    (i32.const 4)
    (i32.load offset=0)
    (drop)
    (i32.const 0)
    (i32.load16_u offset=0)
    (drop)
    (i32.const 0)
    (i32.load16_s offset=0)
    (drop)
    (i32.const 0)
    (i32.load8_u offset=0)
    (drop)
    (i32.const 0)
    (i32.load8_s offset=0)
    (drop)
  )

)
