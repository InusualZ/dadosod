#[inline]
pub(crate) fn align(address: u32, alignment: u32) -> u32 {
    !(alignment - 1u32) & (alignment + address) - 1
}

#[inline]
pub(crate) fn is_aligned(address: u32, alignment: u32) -> bool {
    address % alignment == 0
}
