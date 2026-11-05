import { test } from 'node:test';
import assert from 'node:assert/strict';
import { amount } from '../src/amount.ts';
test('atomic amounts retain precision above JavaScript safe integer range',()=>{
  assert.equal(amount('9007199254740993'),'9,007.199254740993');
  assert.equal(amount('18446744073709551615'),'18,446,744.073709551615');
  assert.equal(amount('1'),'0.000000000001');assert.equal(amount('10000000000'),'0.01');assert.equal(amount('0'),'0.00');
});
test('unknown values are not silently presented as zero',()=>{
  assert.equal(amount(null),'—');assert.equal(amount(undefined),'—');
  for(const bad of ['-1','1.2','NaN','1e12',''])assert.throws(()=>amount(bad));
});
