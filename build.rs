fn main() {
    println!("cargo:rerun-if-changed=assets/agentgate.rc");
    println!("cargo:rerun-if-changed=assets/AppIcon.ico");

    #[cfg(target_os = "windows")]
    {
        let _ = embed_resource::compile("assets/agentgate.rc", embed_resource::NONE)
            .manifest_optional();
    }
}
