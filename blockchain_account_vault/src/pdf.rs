//! Renders backup sheets to a PDF: one page per key file, each carrying the
//! file's name, the account address when it is an account, a QR code and a
//! mnemonic of the (optionally encrypted) secret, for offline / printed storage.

use anyhow::{Result, bail};
use printpdf::path::PaintMode;
use printpdf::{BuiltinFont, Color, Greyscale, Mm, PdfDocument, PdfLayerReference, Rect};
use qrcode::{Color as QrColor, QrCode};

/// One key file's worth of printable data. `qr_payload` is the text encoded into
/// the QR code (base64 of the secret bytes); `mnemonic` is the word-list form of
/// the same secret.
pub struct BackupPage {
    pub name: String,
    /// the account's address, or `None` for a secret that is not an account.
    pub address: Option<String>,
    pub encrypted: bool,
    /// how many bytes the QR code and the mnemonic encode. Printed on the page
    /// because decoding the mnemonic needs it (`mnemonic_to_bytes`).
    pub secret_len: usize,
    pub qr_payload: String,
    pub mnemonic: String,
}

/// The most words a page has room for beneath the QR code.
pub const MAX_MNEMONIC_WORDS: usize = MNEMONIC_WORDS_PER_LINE * MNEMONIC_LINES;

const PAGE_W_MM: f32 = 210.0;
const PAGE_H_MM: f32 = 297.0;
const MARGIN_MM: f32 = 20.0;
const QR_SIZE_MM: f32 = 80.0;
const QR_TOP_MM: f32 = 248.0;
const MNEMONIC_WORDS_PER_LINE: usize = 6;
const MNEMONIC_LINES: usize = 18;

/// Render all `pages` into a single PDF (one page each) and return its bytes.
pub fn render_backup_pdf(pages: &[BackupPage]) -> Result<Vec<u8>> {
    if pages.is_empty() {
        bail!("no key files to print");
    }
    for page in pages {
        let words = page.mnemonic.split_whitespace().count();
        if words > MAX_MNEMONIC_WORDS {
            bail!(
                "'{}' needs {words} mnemonic words, and a page holds {MAX_MNEMONIC_WORDS}",
                page.name
            );
        }
    }

    let (doc, first_page, first_layer) =
        PdfDocument::new("key file backup", Mm(PAGE_W_MM), Mm(PAGE_H_MM), "layer 1");
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    for (i, page) in pages.iter().enumerate() {
        let (page_idx, layer_idx) = if i == 0 {
            (first_page, first_layer)
        } else {
            doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "layer 1")
        };
        let layer = doc.get_page(page_idx).get_layer(layer_idx);

        // Title, address and status.
        layer.use_text(&page.name, 20.0, Mm(MARGIN_MM), Mm(273.0), &font_bold);
        let id = match &page.address {
            Some(address) => format!("id: {address}"),
            None => "secret (not an account)".to_string(),
        };
        layer.use_text(id, 11.0, Mm(MARGIN_MM), Mm(263.0), &mono);
        let subject = if page.address.is_some() {
            "private key"
        } else {
            "secret"
        };
        let status = if page.encrypted {
            format!(
                "{subject}: ENCRYPTED (AES-256-GCM, Argon2id), {} bytes",
                page.secret_len
            )
        } else {
            format!(
                "{subject}: PLAINTEXT (not encrypted), {} bytes",
                page.secret_len
            )
        };
        layer.use_text(status, 10.0, Mm(MARGIN_MM), Mm(255.0), &font);

        // QR code of the (base64) payload.
        draw_qr(&layer, &page.qr_payload)?;

        // Mnemonic, wrapped a few words per line beneath the QR.
        layer.use_text("mnemonic:", 11.0, Mm(MARGIN_MM), Mm(150.0), &font_bold);
        let words: Vec<&str> = page.mnemonic.split_whitespace().collect();
        let mut y = 142.0f32;
        for chunk in words.chunks(MNEMONIC_WORDS_PER_LINE) {
            layer.use_text(chunk.join("  "), 11.0, Mm(MARGIN_MM), Mm(y), &mono);
            y -= 6.5;
        }
    }

    Ok(doc.save_to_bytes()?)
}

/// Draw the QR code for `payload` as filled squares in the top-left region.
fn draw_qr(layer: &PdfLayerReference, payload: &str) -> Result<()> {
    let code = QrCode::new(payload.as_bytes())?;
    let width = code.width();
    let colors = code.to_colors();
    let module = QR_SIZE_MM / width as f32;

    layer.set_fill_color(Color::Greyscale(Greyscale::new(0.0, None)));
    for row in 0..width {
        for col in 0..width {
            if colors[row * width + col] != QrColor::Dark {
                continue;
            }
            let x0 = MARGIN_MM + col as f32 * module;
            let y1 = QR_TOP_MM - row as f32 * module;
            let y0 = y1 - module;
            let rect =
                Rect::new(Mm(x0), Mm(y0), Mm(x0 + module), Mm(y1)).with_mode(PaintMode::Fill);
            layer.add_rect(rect);
        }
    }
    Ok(())
}
