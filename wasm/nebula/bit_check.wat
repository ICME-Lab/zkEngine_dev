  (func (;0;) (param i64 i64) (result i64)
    local.get 1
    i64.const 1
    i64.and
    local.tee 1
    i64.const 1
    i64.xor
    local.get 0
    i64.const -1
    i64.xor
    i64.const 1
    i64.and
    i64.mul
    local.get 1
    local.get 0
    i64.and
    i64.add)
  (export "bit_check" (func 0))