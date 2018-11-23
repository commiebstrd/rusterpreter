use alloc::vec::*;
use core::mem::size_of;

pub fn slice_to_u32_ntoh(val: &[u8]) -> u32 {
  if val.len() < size_of::<u32>() {
    panic!{"slice_to_u32 slice too small: {}", val.len()};
  }
  // net to host conversion
  (val[3] as u32).rotate_left(24) | //hi bits
  (val[2] as u32).rotate_left(16) |
  (val[1] as u32).rotate_left(8) |
  (val[0] as u32)                   //low bits
}
pub fn slice_to_u32_hton(val: &[u8]) -> u32 {
  if val.len() < size_of::<u32>() {
    panic!{"slice_to_u32 slice too small: {}", val.len()};
  }
  // net to host conversion
  (val[0] as u32).rotate_left(24) | //hi bits
  (val[1] as u32).rotate_left(16) |
  (val[2] as u32).rotate_left(8) |
  (val[3] as u32)                   //low bits
}

pub fn u32_to_vec_hton(val: u32) -> Vec<u8> {
  let mut vec: Vec<u8> = Vec::with_capacity(4);
  // host to net conversion
  vec.push((val & 0xFF) as u8);
  vec.push(((val & 0xFF00).rotate_right(8)) as u8);
  vec.push(((val & 0xFF0000).rotate_right(16)) as u8);
  vec.push(((val & 0xFF000000).rotate_right(24)) as u8);
  vec
}
pub fn u32_to_vec_ntoh(val: u32) -> Vec<u8> {
  let mut vec: Vec<u8> = Vec::with_capacity(4);
  // net to host conversion
  vec.push(((val & 0xFF000000).rotate_right(24)) as u8);
  vec.push(((val & 0xFF0000).rotate_right(16)) as u8);
  vec.push(((val & 0xFF00).rotate_right(8)) as u8);
  vec.push((val & 0xFF) as u8);
  vec
}
