(module
  (type (;0;) (func (param i64 i64) (result i64)))
  (func (;0;) (type 0) (param i64 i64) (result i64)
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
  (func (;1;) (type 0) (param i64 i64) (result i64)
    (local i64 i64 i64 i64)
    i64.const 0
    local.set 2
    i64.const 1
    local.set 3
    loop  ;; label = @1
      local.get 1
      local.get 2
      i64.const 1
      i64.add
      local.tee 4
      i64.shr_u
      i64.const 1
      i64.and
      local.tee 5
      i64.const 1
      i64.xor
      local.get 0
      local.get 4
      i64.shr_s
      local.tee 4
      i64.const -1
      i64.xor
      i64.const 1
      i64.and
      i64.mul
      local.get 5
      local.get 4
      i64.and
      i64.add
      local.get 1
      local.get 2
      i64.shr_u
      i64.const 1
      i64.and
      local.tee 4
      i64.const 1
      i64.xor
      local.get 0
      local.get 2
      i64.shr_s
      local.tee 5
      i64.const -1
      i64.xor
      i64.const 1
      i64.and
      i64.mul
      local.get 4
      local.get 5
      i64.and
      i64.add
      local.get 3
      i64.mul
      i64.mul
      local.set 3
      local.get 2
      i64.const 2
      i64.add
      local.tee 2
      i64.const 64
      i64.ne
      br_if 0 (;@1;)
    end
    local.get 3)
  (export "bit_check" (func 0))
  (export "eq_func" (func 1))
)