use crate::wasm4;

pub fn set_draw_color(idx: u16) {
    unsafe { *wasm4::DRAW_COLORS = idx }
}

pub fn set_palette(palette: [u32; 4]) {
    unsafe {
        *wasm4::PALETTE = palette;
    }
}
