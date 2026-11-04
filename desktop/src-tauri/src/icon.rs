// Shared procedural pixels for the Windows resource and native tray.
pub fn rgba() -> Vec<u8> {
    let mut pixels = vec![0u8; 32 * 32 * 4];
    for y in 0usize..32 {
        for x in 0usize..32 {
            let i = (y * 32 + x) * 4;
            if (3..29).contains(&x) && (3..29).contains(&y) {
                let lock = ((10..22).contains(&x) && (14..25).contains(&y))
                    || ((12..20).contains(&x) && (8..17).contains(&y) && !(14..18).contains(&x));
                pixels[i..i + 4].copy_from_slice(if lock {
                    &[238, 244, 255, 255]
                } else {
                    &[47, 99, 224, 255]
                });
            }
        }
    }
    pixels
}
