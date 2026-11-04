#[path = "src/icon.rs"]
mod icon;

fn main() {
    // Uncompressed 32-bit ICO generated using std only; tray uses the same RGBA.
    let pixels = icon::rgba();
    let dib_size = 40u32 + 32 * 32 * 4 + 32 * 4;
    let mut ico = vec![0, 0, 1, 0, 1, 0, 32, 32, 0, 0, 1, 0, 32, 0];
    ico.extend_from_slice(&dib_size.to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    ico.extend_from_slice(&40u32.to_le_bytes());
    ico.extend_from_slice(&32i32.to_le_bytes());
    ico.extend_from_slice(&64i32.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&[0u8; 24]);
    for y in (0..32).rev() {
        for x in 0..32 {
            let i = (y * 32 + x) * 4;
            ico.extend_from_slice(&[pixels[i + 2], pixels[i + 1], pixels[i], pixels[i + 3]]);
        }
    }
    ico.extend_from_slice(&[0u8; 128]);
    let path =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo output directory"))
            .join("vault.ico");
    std::fs::write(&path, ico).expect("Generate Windows resource icon");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path(path)),
    )
    .expect("Build native Windows resources");
    println!("cargo:rerun-if-changed=src/icon.rs");
}
