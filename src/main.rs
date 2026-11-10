#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod models;
pub mod prompt_tpl;
pub mod proxy;
pub mod ssh_relay;
pub mod storage;
pub mod tray;
pub mod ui;

use gpui::{
    App, Application, Bounds, TitlebarOptions, WindowBounds, WindowKind, WindowOptions, prelude::*,
    px, size,
};
use ui::{AgentGateWorkbench, QuitApp, register_workbench_keys};

fn main() {
    if let Ok(showcase_path) = std::env::var("AGENTGATE_EXPORT_ICON_SHOWCASE")
        && !showcase_path.trim().is_empty()
    {
        tray::export_icon_design_showcase(std::path::Path::new(&showcase_path))
            .expect("导出菜单栏图标设计预览失败");
        return;
    }

    // 预热后台 Tokio SSH 运行时
    let _ = ssh_relay::global_tokio_runtime();

    Application::new().run(|cx: &mut App| {
        // 初始化菜单栏/系统托盘图标，并隐藏 Dock / 任务栏图标
        tray::init_platform_tray_and_hide_dock();

        register_workbench_keys(cx);
        cx.on_action(|_: &QuitApp, cx| cx.quit());

        let bounds = Bounds::centered(None, size(px(1240.0), px(780.0)), cx);
        let window_kind = if cfg!(target_os = "macos") {
            // macOS 下已通过 NSApplicationActivationPolicyAccessory 隐藏 Dock 图标
            WindowKind::Normal
        } else {
            // Windows / Linux 下使用 PopUp (WS_EX_TOOLWINDOW / Notification) 隐藏任务栏图标
            WindowKind::PopUp
        };

        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("AgentGate".into()),
                    appears_transparent: false,
                    traffic_light_position: None,
                }),
                focus: true,
                show: true,
                kind: window_kind,
                ..Default::default()
            },
            |window, cx| {
                // 点击窗口关闭按钮时仅收起到菜单栏，不中断正在运行的本地 SSH 中转
                window.on_window_should_close(cx, |_win, _cx| {
                    tray::platform_set_window_visible(false);
                    false
                });
                cx.new(|cx| AgentGateWorkbench::new(window, cx))
            },
        )
        .expect("打开 AgentGate GPUI 主窗口失败");

        cx.activate(true);
        tray::platform_set_window_visible(true);
    });
}
