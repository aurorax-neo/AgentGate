use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};

use anyhow::{Context, Result};
use image::{ ImageBuffer, ImageFormat, Rgba };

/// 菜单栏 / 系统托盘向 GPUI 主线程发送的控制指令
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    ToggleWindow,
    ShowWindow,
    HideWindow,
    QuitApp,
}

static TRAY_TX: OnceLock<Mutex<mpsc::Sender<TrayCommand>>> = OnceLock::new();
static TRAY_RX: OnceLock<Mutex<mpsc::Receiver<TrayCommand>>> = OnceLock::new();
static WINDOW_VISIBLE: AtomicBool = AtomicBool::new(true);

fn ensure_tray_channel() -> &'static Mutex<mpsc::Sender<TrayCommand>> {
    TRAY_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        let _ = TRAY_RX.set(Mutex::new(rx));
        Mutex::new(tx)
    })
}

pub fn send_tray_command(cmd: TrayCommand) {
    if let Ok(guard) = ensure_tray_channel().lock() {
        let _ = guard.send(cmd);
    }
}

pub fn poll_tray_command() -> Option<TrayCommand> {
    #[cfg(target_os = "macos")]
    macos_tray::log_status_bar_frame_once();

    let rx_lock = TRAY_RX.get()?;
    let guard = rx_lock.lock().ok()?;
    guard.try_recv().ok()
}

pub fn is_window_visible() -> bool {
    WINDOW_VISIBLE.load(Ordering::SeqCst)
}

pub fn set_window_visible_flag(visible: bool) {
    WINDOW_VISIBLE.store(visible, Ordering::SeqCst);
}

/// 计算 AgentGate 专属图标（双弧对向隔离环 + 中心安全中转核）在归一化坐标 `[-1.0, 1.0]` 下的有符号距离覆盖度
///
/// 设计语言：
/// - 外层为粗壮圆环（`0.44 <= r <= 0.82`），被 45° 斜向隔离气隙切割为左上（Agent 侧）与右下（Host 侧）两段对称圆弧，直接呼应参考截图风格；
/// - 圆环中心悬浮一枚圆润菱形/圆形安全中转核（`r <= 0.16`），象征 `127.0.0.1` 凭证隔离中转节点。
#[inline]
fn sample_gate_icon_point(nx: f32, ny: f32) -> bool {
    let r = (nx * nx + ny * ny).sqrt();

    // 中心隔离核（带轻微八角/圆融感，保证在 18x18pt 小尺寸下依然清晰醒目）
    if r <= 0.155 {
        return true;
    }

    // 外层双弧隔离环
    if (0.435..=0.825).contains(&r) {
        // 45° 对角线气隙：|(nx - ny)| / sqrt(2) 控制左下到右上切口（与参考截图一致的 45° 斜切缺口）
        let diag_dist = ((nx - ny) * std::f32::consts::FRAC_1_SQRT_2).abs();
        if diag_dist >= 0.175 {
            return true;
        }
    }
    false
}

/// 使用 4x4 超采样抗锯齿计算单个像素的不透明度 (0.0 ~ 1.0)
pub fn sample_gate_icon_alpha(px_x: u32, px_y: u32, size: u32) -> f32 {
    let mut hits = 0u32;
    let inv_size = 1.0 / (size as f32);
    for sy in 0..4 {
        for sx in 0..4 {
            let u = (px_x as f32 + (sx as f32 + 0.5) * 0.25) * inv_size;
            let v = (px_y as f32 + (sy as f32 + 0.5) * 0.25) * inv_size;
            let nx = u * 2.0 - 1.0;
            let ny = 1.0 - v * 2.0;
            if sample_gate_icon_point(nx, ny) {
                hits += 1;
            }
        }
    }
    (hits as f32) / 16.0
}

/// 生成单色模版图标 RGBA 像素（macOS Template Image 使用黑色 + Alpha，系统自动适配深浅色菜单栏为纯白或深灰）
pub fn generate_template_icon_rgba(size: u32, rgb_color: [u8; 3]) -> Vec<u8> {
    let mut buf = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let alpha = (sample_gate_icon_alpha(x, y, size) * 255.0).round() as u8;
            buf.push(rgb_color[0]);
            buf.push(rgb_color[1]);
            buf.push(rgb_color[2]);
            buf.push(alpha);
        }
    }
    buf
}

/// 生成 PNG 字节流（用于 macOS `NSStatusItem` `@2x` 模版图标及跨平台图标加载）
pub fn generate_template_icon_png(size: u32, rgb_color: [u8; 3]) -> Vec<u8> {
    let raw = generate_template_icon_rgba(size, rgb_color);
    let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
        ImageBuffer::from_raw(size, size, raw).expect("构建菜单栏图标缓冲区失败");
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, ImageFormat::Png)
        .expect("编码菜单栏 PNG 图标失败");
    out.into_inner()
}

/// 导出图标设计预览图（包含高分辨率品牌图标、深蓝色菜单栏实机效果对比与浅色菜单栏效果对比）
pub fn export_icon_design_showcase(output_path: &Path) -> Result<()> {
    let width = 840u32;
    let height = 280u32;
    let mut img = ImageBuffer::from_pixel(width, height, Rgba([13, 17, 23, 255]));

    // 1. 左侧：绘制 180x180 高清品牌图标（深青蓝圆角底座 + 纯白双弧隔离环）
    let card_x0 = 40i32;
    let card_y0 = 50i32;
    let card_size = 180i32;
    for py in 0..card_size {
        for px in 0..card_size {
            let cx = (px as f32 - 90.0).abs() - 54.0;
            let cy = (py as f32 - 90.0).abs() - 54.0;
            let dist = (cx.max(0.0).powi(2) + cy.max(0.0).powi(2)).sqrt() + cx.max(cy).min(0.0) - 34.0;
            if dist <= 1.0 {
                let edge_alpha = (0.5 - dist * 0.5).clamp(0.0, 1.0);
                let grad_t = (py as f32) / (card_size as f32);
                let bg_r = (14.0 * (1.0 - grad_t) + 9.0 * grad_t) as u8;
                let bg_g = (116.0 * (1.0 - grad_t) + 72.0 * grad_t) as u8;
                let bg_b = (168.0 * (1.0 - grad_t) + 125.0 * grad_t) as u8;

                let icon_a = if (24..156).contains(&px) && (24..156).contains(&py) {
                    sample_gate_icon_alpha((px - 24) as u32, (py - 24) as u32, 132)
                } else {
                    0.0
                };

                let r = (bg_r as f32 * (1.0 - icon_a) + 245.0 * icon_a) as u8;
                let g = (bg_g as f32 * (1.0 - icon_a) + 250.0 * icon_a) as u8;
                let b = (bg_b as f32 * (1.0 - icon_a) + 255.0 * icon_a) as u8;
                let out_x = (card_x0 + px) as u32;
                let out_y = (card_y0 + py) as u32;
                let base = img.get_pixel(out_x, out_y).0;
                img.put_pixel(
                    out_x,
                    out_y,
                    Rgba([
                        (base[0] as f32 * (1.0 - edge_alpha) + r as f32 * edge_alpha) as u8,
                        (base[1] as f32 * (1.0 - edge_alpha) + g as f32 * edge_alpha) as u8,
                        (base[2] as f32 * (1.0 - edge_alpha) + b as f32 * edge_alpha) as u8,
                        255,
                    ]),
                );
            }
        }
    }

    // 2. 右上：模拟用户截图同款深蓝背景菜单栏 (1:1 还原截图配色 #0069B4 + 纯白菜单栏图标)
    let bar1_x0 = 270u32;
    let bar1_y0 = 48u32;
    let bar_w = 520u32;
    let bar_h = 82u32;
    for y in 0..bar_h {
        for x in 0..bar_w {
            let color = if y < 62 {
                Rgba([0, 106, 182, 255])
            } else if y == 62 {
                Rgba([0, 62, 112, 255])
            } else {
                Rgba([235, 237, 239, 255])
            };
            img.put_pixel(bar1_x0 + x, bar1_y0 + y, color);
        }
    }
    let icon_sz = 38u32;
    let ic1_x = bar1_x0 + 240;
    let ic1_y = bar1_y0 + 12;
    for iy in 0..icon_sz {
        for ix in 0..icon_sz {
            let a = sample_gate_icon_alpha(ix, iy, icon_sz);
            if a > 0.0 {
                let p = img.get_pixel(ic1_x + ix, ic1_y + iy).0;
                img.put_pixel(
                    ic1_x + ix,
                    ic1_y + iy,
                    Rgba([
                        (p[0] as f32 * (1.0 - a) + 242.0 * a) as u8,
                        (p[1] as f32 * (1.0 - a) + 246.0 * a) as u8,
                        (p[2] as f32 * (1.0 - a) + 250.0 * a) as u8,
                        255,
                    ]),
                );
            }
        }
    }

    // 3. 右下：模拟浅色壁纸菜单栏 (#E8ECEF + 深炭灰菜单栏图标)
    let bar2_x0 = 270u32;
    let bar2_y0 = 152u32;
    for y in 0..bar_h {
        for x in 0..bar_w {
            let color = if y < 62 {
                Rgba([232, 236, 242, 255])
            } else if y == 62 {
                Rgba([198, 205, 214, 255])
            } else {
                Rgba([24, 29, 38, 255])
            };
            img.put_pixel(bar2_x0 + x, bar2_y0 + y, color);
        }
    }
    let ic2_x = bar2_x0 + 240;
    let ic2_y = bar2_y0 + 12;
    for iy in 0..icon_sz {
        for ix in 0..icon_sz {
            let a = sample_gate_icon_alpha(ix, iy, icon_sz);
            if a > 0.0 {
                let p = img.get_pixel(ic2_x + ix, ic2_y + iy).0;
                img.put_pixel(
                    ic2_x + ix,
                    ic2_y + iy,
                    Rgba([
                        (p[0] as f32 * (1.0 - a) + 28.0 * a) as u8,
                        (p[1] as f32 * (1.0 - a) + 33.0 * a) as u8,
                        (p[2] as f32 * (1.0 - a) + 43.0 * a) as u8,
                        255,
                    ]),
                );
            }
        }
    }

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    img.save(output_path)
        .with_context(|| format!("保存图标预览图失败: {}", output_path.display()))
}

/// 初始化当前平台的菜单栏/系统托盘图标，并隐藏 Dock / 任务栏图标
pub fn init_platform_tray_and_hide_dock() {
    let _ = ensure_tray_channel();

    #[cfg(target_os = "macos")]
    macos_tray::install();

    #[cfg(target_os = "windows")]
    windows_tray::install();

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    linux_tray::install();
}

/// 在系统层面切换应用主窗口的显示与隐藏（保持后台 SSH 中转持续运行）
pub fn platform_set_window_visible(visible: bool) {
    set_window_visible_flag(visible);

    #[cfg(target_os = "macos")]
    macos_tray::set_visible(visible);

    #[cfg(target_os = "windows")]
    windows_tray::set_visible(visible);
}

#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
mod macos_tray {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Once;

    use cocoa::appkit::{
        NSApplication, NSApplicationActivationPolicyAccessory,
    };
    use cocoa::base::{BOOL, NO, YES, id, nil};
    use cocoa::foundation::{NSData, NSSize, NSString};
    use objc::declare::ClassDecl;
    use objc::runtime::{Class, Object, Sel};
    use objc::{class, msg_send, sel, sel_impl};

    use super::{TrayCommand, generate_template_icon_png, send_tray_command};

    static REGISTER_TARGET: Once = Once::new();
    static STATUS_BUTTON_PTR: AtomicUsize = AtomicUsize::new(0);
    static LOGGED_FRAME: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_status_bar_click(_this: &Object, _cmd: Sel, _sender: id) {
        send_tray_command(TrayCommand::ToggleWindow);
    }

    fn target_class() -> &'static Class {
        REGISTER_TARGET.call_once(|| unsafe {
            let superclass = class!(NSObject);
            if let Some(mut decl) = ClassDecl::new("AgentGateStatusBarTarget", superclass) {
                decl.add_method(
                    sel!(onStatusBarClick:),
                    on_status_bar_click as extern "C" fn(&Object, Sel, id),
                );
                decl.register();
            }
        });
        class!(AgentGateStatusBarTarget)
    }

    pub fn install() {
        unsafe {
            // 1. 切换为 Accessory 模式：不显示 Dock 图标，仅驻留系统右上角菜单栏
            let app = NSApplication::sharedApplication(nil);
            app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);

            // 2. 创建系统菜单栏 NSStatusItem (NSVariableStatusItemLength = -1.0)
            let status_bar: id = msg_send![class!(NSStatusBar), systemStatusBar];
            let status_item: id = msg_send![status_bar, statusItemWithLength: 28.0_f64];
            let _: id = msg_send![status_item, retain];
            let _: () = msg_send![status_item, setVisible: YES];

            // 3. 生成 36x36 (@2x Retina 对应 18x18pt) 专属双弧隔离环模版图标
            let png_bytes = generate_template_icon_png(36, [0, 0, 0]);
            let ns_data: id = NSData::dataWithBytes_length_(
                nil,
                png_bytes.as_ptr() as *const c_void,
                png_bytes.len() as u64,
            );
            let ns_image: id = msg_send![class!(NSImage), alloc];
            let ns_image: id = msg_send![ns_image, initWithData: ns_data];
            let _: () = msg_send![ns_image, setSize: NSSize::new(18.0, 18.0)];
            let _: () = msg_send![ns_image, setTemplate: YES];

            // 4. 绑定图标与点击事件到 NSStatusBarButton
            let button: id = msg_send![status_item, button];
            if button != nil {
                let _: id = msg_send![ns_image, retain];
                let _: () = msg_send![button, setImage: ns_image];
                let tooltip =
                    NSString::alloc(nil).init_str("AgentGate — 本地 SSH 安全隔离中转台 (点击显示/收起)");
                let _: () = msg_send![button, setToolTip: tooltip];

                let target: id = msg_send![target_class(), new];
                let _: id = msg_send![target, retain];
                let _: () = msg_send![button, setTarget: target];
                let _: () = msg_send![button, setAction: sel!(onStatusBarClick:)];
                STATUS_BUTTON_PTR.store(button as usize, Ordering::SeqCst);
            }
        }
    }

    pub fn log_status_bar_frame_once() {
        if std::env::var("AGENTGATE_DEBUG_TRAY").as_deref() != Ok("1") {
            return;
        }
        if LOGGED_FRAME.swap(true, Ordering::SeqCst) {
            return;
        }
        let ptr = STATUS_BUTTON_PTR.load(Ordering::SeqCst);
        if ptr == 0 {
            return;
        }
        unsafe {
            let button = ptr as id;
            let btn_win: id = msg_send![button, window];
            if btn_win != nil {
                let frame: cocoa::foundation::NSRect = msg_send![btn_win, frame];
                println!(
                    "TRAY_BAR_FRAME X={} Y={} W={} H={}",
                    frame.origin.x, frame.origin.y, frame.size.width, frame.size.height
                );
            }
        }
    }

    pub fn set_visible(visible: bool) {
        unsafe {
            let app = NSApplication::sharedApplication(nil);
            let _: BOOL = msg_send![
                app,
                setActivationPolicy: NSApplicationActivationPolicyAccessory
            ];
            let windows: id = msg_send![app, windows];
            let count: usize = msg_send![windows, count];
            for i in 0..count {
                let win: id = msg_send![windows, objectAtIndex: i];
                let class_name: id = msg_send![win, className];
                let c_str: *const i8 = msg_send![class_name, UTF8String];
                let name_str = if !c_str.is_null() {
                    std::ffi::CStr::from_ptr(c_str).to_string_lossy()
                } else {
                    std::borrow::Cow::Borrowed("")
                };
                // 仅控制 GPUI 主工作台窗口，绝不触碰 NSStatusBarWindow
                if !name_str.contains("GPUI") {
                    continue;
                }
                if visible {
                    let _: () = msg_send![win, makeKeyAndOrderFront: nil];
                } else {
                    let _: () = msg_send![win, orderOut: nil];
                }
            }
            if visible {
                let _: () = msg_send![app, activateIgnoringOtherApps: YES];
            } else {
                let _: () = msg_send![app, hide: nil];
                let _ = NO;
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_tray {
    use std::mem::size_of;
    use std::sync::atomic::{AtomicIsize, Ordering};

    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{
         NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateIcon, CreateWindowExW, DefWindowProcW, DispatchMessageW, GWL_EXSTYLE,
        GetForegroundWindow, GetMessageW, GetWindowLongPtrW, MSG, RegisterClassW, SW_HIDE,
        SW_SHOW, SetForegroundWindow, SetWindowLongPtrW, ShowWindow, TranslateMessage,
        WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
        WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
    };
    use windows::core::PCWSTR;

    use super::{TrayCommand, generate_template_icon_rgba, send_tray_command};

    const WM_TRAYICON: u32 = WM_APP + 0x47;
    static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);

    unsafe extern "system" fn tray_wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_TRAYICON {
            let event = (lparam.0 & 0xffff) as u32;
            if event == WM_LBUTTONUP || event == WM_RBUTTONUP {
                send_tray_command(TrayCommand::ToggleWindow);
            }
            return LRESULT(0);
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub fn install() {
        std::thread::spawn(|| unsafe {
            let instance = GetModuleHandleW(None).unwrap_or_default();
            let class_name: Vec<u16> = "AgentGateTrayHostClass\0".encode_utf16().collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(tray_wnd_proc),
                hInstance: instance.into(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            let _ = RegisterClassW(&wc);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(class_name.as_ptr()),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                None,
                None,
                Some(instance.into()),
                None,
            )
            .unwrap_or_default();

            let size = 32u32;
            let rgba = generate_template_icon_rgba(size, [245, 250, 255]);
            let mut bgra = vec![0u8; rgba.len()];
            for (dst, src) in bgra.chunks_exact_mut(4).zip(rgba.chunks_exact(4)) {
                dst[0] = src[2];
                dst[1] = src[1];
                dst[2] = src[0];
                dst[3] = src[3];
            }
            let and_mask = vec![0u8; ((size * size) / 8) as usize];
            let hicon = CreateIcon(
                Some(instance.into()),
                size as i32,
                size as i32,
                1,
                32,
                and_mask.as_ptr(),
                bgra.as_ptr(),
            )
            .unwrap_or_default();

            let mut nid = NOTIFYICONDATAW {
                cbSize: size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1,
                uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
                uCallbackMessage: WM_TRAYICON,
                hIcon: hicon,
                ..Default::default()
            };
            let tip: Vec<u16> = "AgentGate — 本地 SSH 隔离中转台\0"
                .encode_utf16()
                .collect();
            let copy_len = tip.len().min(nid.szTip.len());
            nid.szTip[..copy_len].copy_from_slice(&tip[..copy_len]);
            let _ = Shell_NotifyIconW(NIM_ADD, &nid);

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
    }

    pub fn set_visible(visible: bool) {
        unsafe {
            let mut raw = MAIN_HWND.load(Ordering::SeqCst);
            if raw == 0 {
                let fg = GetForegroundWindow();
                if !fg.0.is_null() {
                    raw = fg.0 as isize;
                    MAIN_HWND.store(raw, Ordering::SeqCst);
                    // 移除任务栏图标（WS_EX_TOOLWINDOW 并不带 WS_EX_APPWINDOW）
                    let ex = GetWindowLongPtrW(fg, GWL_EXSTYLE);
                    let new_ex =
                        (ex & !(WS_EX_APPWINDOW.0 as isize)) | (WS_EX_TOOLWINDOW.0 as isize);
                    let _ = SetWindowLongPtrW(fg, GWL_EXSTYLE, new_ex);
                }
            }
            if raw != 0 {
                let hwnd = HWND(raw as *mut _);
                if visible {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                    let _ = SetForegroundWindow(hwnd);
                } else {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod linux_tray {
    use ksni::TrayMethods;

    use super::{TrayCommand, generate_template_icon_rgba, send_tray_command};

    struct AgentGateLinuxTray;

    impl ksni::Tray for AgentGateLinuxTray {
        fn id(&self) -> String {
            "agent-gate-ssh-relay".into()
        }

        fn title(&self) -> String {
            "AgentGate".into()
        }

        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            let size = 32u32;
            let rgba = generate_template_icon_rgba(size, [245, 250, 255]);
            let mut argb = Vec::with_capacity(rgba.len());
            for px in rgba.chunks_exact(4) {
                argb.push(px[3]);
                argb.push(px[0]);
                argb.push(px[1]);
                argb.push(px[2]);
            }
            vec![ksni::Icon {
                width: size as i32,
                height: size as i32,
                data: argb,
            }]
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            send_tray_command(TrayCommand::ToggleWindow);
        }

        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::*;
            vec![
                StandardItem {
                    label: "显示 / 隐藏 AgentGate 工作台".into(),
                    activate: Box::new(|_| send_tray_command(TrayCommand::ToggleWindow)),
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "退出 AgentGate".into(),
                    activate: Box::new(|_| send_tray_command(TrayCommand::QuitApp)),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }

    pub fn install() {
        crate::ssh_relay::global_tokio_runtime().spawn(async {
            if let Ok(handle) = AgentGateLinuxTray.spawn().await {
                std::mem::forget(handle);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_menubar_icon_generation_and_showcase_export() {
        // 1. 验证 36x36 (@2x Retina) 菜单栏图标包含透明背景与非空双弧前景
        let rgba = generate_template_icon_rgba(36, [255, 255, 255]);
        assert_eq!(rgba.len(), 36 * 36 * 4);
        let opaque_pixels = rgba.chunks_exact(4).filter(|px| px[3] > 180).count();
        let transparent_pixels = rgba.chunks_exact(4).filter(|px| px[3] == 0).count();
        assert!(opaque_pixels > 150, "icon foreground pixels too few");
        assert!(transparent_pixels > 400, "icon background should be transparent");

        // 2. 验证 PNG 编码头正确
        let png = generate_template_icon_png(36, [0, 0, 0]);
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        // 3. 验证托盘命令通道收发正常
        send_tray_command(TrayCommand::ToggleWindow);
        assert_eq!(poll_tray_command(), Some(TrayCommand::ToggleWindow));

        // 4. 验证导出高清图标设计预览图
        let tmp = tempfile::tempdir().expect("tempdir");
        let out_path = tmp.path().join("icon-showcase.png");
        export_icon_design_showcase(&out_path).expect("export showcase");
        assert!(out_path.exists());
    }
}
