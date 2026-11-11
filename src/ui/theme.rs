use gpui::{Hsla, Rgba, hsla, rgb};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkbenchTheme {
    pub is_dark: bool,
    pub bg_app: Rgba,
    pub bg_surface: Rgba,
    pub bg_elevated: Rgba,
    pub bg_subtle: Rgba,
    pub bg_code: Rgba,
    pub border: Rgba,
    pub border_focus: Rgba,
    pub text_primary: Rgba,
    pub text_secondary: Rgba,
    pub text_muted: Rgba,
    pub accent: Rgba,
    pub accent_hover: Rgba,
    pub accent_soft: Hsla,
    pub success: Rgba,
    pub success_soft: Hsla,
    pub warning: Rgba,
    pub danger: Rgba,
    pub danger_hover: Rgba,
    pub danger_soft: Hsla,
}

impl WorkbenchTheme {
    pub fn dark() -> Self {
        Self {
            is_dark: true,
            bg_app: rgb(0x0e1013),
            bg_surface: rgb(0x15181d),
            bg_elevated: rgb(0x1c2026),
            bg_subtle: rgb(0x242931),
            bg_code: rgb(0x0a0c0e),
            border: rgb(0x2a303a),
            border_focus: rgb(0x10b981),
            text_primary: rgb(0xf3f4f6),
            text_secondary: rgb(0x9ca3af),
            text_muted: rgb(0x6b7280),
            accent: rgb(0x0d9488),
            accent_hover: rgb(0x14b8a6),
            accent_soft: hsla(0.48, 0.78, 0.40, 0.16),
            success: rgb(0x10b981),
            success_soft: hsla(0.44, 0.80, 0.42, 0.16),
            warning: rgb(0xf59e0b),
            danger: rgb(0xe11d48),
            danger_hover: rgb(0xf43f5e),
            danger_soft: hsla(0.96, 0.82, 0.52, 0.16),
        }
    }

    pub fn light() -> Self {
        Self {
            is_dark: false,
            bg_app: rgb(0xf3f4f6),
            bg_surface: rgb(0xffffff),
            bg_elevated: rgb(0xf8f9fa),
            bg_subtle: rgb(0xebedf0),
            bg_code: rgb(0xf1f3f5),
            border: rgb(0xd8dde3),
            border_focus: rgb(0x0d9488),
            text_primary: rgb(0x111827),
            text_secondary: rgb(0x4b5563),
            text_muted: rgb(0x6b7280),
            accent: rgb(0x0f766e),
            accent_hover: rgb(0x0d9488),
            accent_soft: hsla(0.48, 0.80, 0.32, 0.10),
            success: rgb(0x059669),
            success_soft: hsla(0.44, 0.85, 0.35, 0.12),
            warning: rgb(0xd97706),
            danger: rgb(0xbe123c),
            danger_hover: rgb(0xe11d48),
            danger_soft: hsla(0.96, 0.80, 0.45, 0.10),
        }
    }
}
