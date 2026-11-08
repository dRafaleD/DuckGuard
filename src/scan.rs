use crate::{
    discovery,
    model::{Finding, Severity},
};
use serde_yaml::Value;
use std::{fs, path::Path};

pub const RULES: &[(&str, &str)] = &[
    ("DG-D001", "Dockerfile final stage user is unspecified"),
    ("DG-D002", "Dockerfile final stage runs as root"),
    ("DG-D003", "Base image uses latest or no tag"),
    ("DG-C001", "Privileged service"),
    ("DG-C002", "Host network or PID namespace"),
    ("DG-C003", "Docker socket mounted"),
    ("DG-C004", "Dangerous capability"),
    ("DG-C005", "Port published on all interfaces"),
    ("DG-C006", "Service explicitly runs as root"),
];
// Keep the finding's source and explanation explicit at each rule call site.
#[allow(clippy::too_many_arguments)]
fn add(
    out: &mut Vec<Finding>,
    file: &Path,
    loc: Option<String>,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: &str,
    recommendation: &'static str,
) {
    out.push(Finding {
        rule_id: id,
        severity,
        title,
        file: file.display().to_string(),
        location: loc,
        detail: detail.to_string(),
        recommendation,
    });
}
pub fn scan_file(file: &Path, out: &mut Vec<Finding>) -> Result<(), String> {
    let data = fs::read_to_string(file).map_err(|e| e.to_string())?;
    if discovery::kind(file) == Some(true) {
        dockerfile(file, &data, out);
        Ok(())
    } else {
        compose(file, &data, out)
    }
}
fn dockerfile(file: &Path, data: &str, out: &mut Vec<Finding>) {
    let mut user: Option<(String, usize)> = None;
    let mut stage = false;
    for (i, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let op = parts.next().unwrap_or("").to_ascii_uppercase();
        let value = parts.next().unwrap_or("").trim();
        if op == "FROM" {
            stage = true;
            user = None;
            let image = value
                .split_whitespace()
                .find(|s| !s.starts_with("--"))
                .unwrap_or("");
            let last = image.rsplit('/').next().unwrap_or(image);
            if !image.contains('$')
                && !image.contains('@')
                && (!last.contains(':') || last.ends_with(":latest"))
                && image != "scratch"
            {
                add(
                    out,
                    file,
                    Some(format!("line {}", i + 1)),
                    "DG-D003",
                    Severity::Low,
                    "Base image is not pinned",
                    "The image uses latest or has no tag.",
                    "Pin an appropriate version or digest.",
                );
            }
        } else if op == "USER" && stage {
            user = Some((value.to_owned(), i + 1));
        }
    }
    if stage {
        match user {
        None => add(out, file, None, "DG-D001", Severity::Medium, "Final stage user is unspecified", "The effective user depends on the base image and cannot be verified from this file.", "Verify the base image user and specify an appropriate non-root USER."),
        Some((u, line)) if matches!(u.split(':').next().unwrap_or(""), "root" | "0") => add(out, file, Some(format!("line {line}")), "DG-D002", Severity::High, "Final stage explicitly uses root", "The final USER instruction selects root.", "Use a dedicated non-root user when possible."),
        _ => {}
    }
    }
}
fn compose(file: &Path, data: &str, out: &mut Vec<Finding>) -> Result<(), String> {
    let root: Value = serde_yaml::from_str(data).map_err(|e| format!("invalid YAML: {e}"))?;
    let services = root
        .get("services")
        .and_then(Value::as_mapping)
        .ok_or("missing or invalid services mapping")?;
    for (name, service) in services {
        let name = name.as_str().unwrap_or("<unknown>");
        let loc = Some(format!("service {name}"));
        if !service.is_mapping() {
            return Err(format!("service {name} must be a mapping"));
        }
        if service.get("privileged").and_then(Value::as_bool) == Some(true) {
            add(
                out,
                file,
                loc.clone(),
                "DG-C001",
                Severity::Critical,
                "Privileged service",
                "Privileged mode grants broad host privileges.",
                "Remove privileged mode and grant only necessary permissions.",
            );
        }
        for key in ["network_mode", "pid"] {
            if service.get(key).and_then(Value::as_str) == Some("host") {
                add(
                    out,
                    file,
                    loc.clone(),
                    "DG-C002",
                    Severity::High,
                    "Host namespace shared",
                    &format!("{key} is set to host."),
                    "Use an isolated namespace where possible.",
                );
            }
        }
        if let Some(volumes) = service.get("volumes").and_then(Value::as_sequence) {
            for v in volumes {
                let source = v
                    .as_str()
                    .and_then(|s| s.split(':').next())
                    .or_else(|| v.get("source").and_then(Value::as_str))
                    .unwrap_or("");
                if source == "/var/run/docker.sock" || source == "/run/docker.sock" {
                    add(
                        out,
                        file,
                        loc.clone(),
                        "DG-C003",
                        Severity::Critical,
                        "Docker socket mounted",
                        "Access to the Docker socket can grant control over the host.",
                        "Remove the socket mount or use a narrowly scoped alternative.",
                    );
                }
            }
        }
        if let Some(caps) = service.get("cap_add").and_then(Value::as_sequence) {
            for cap in caps {
                if matches!(
                    cap.as_str(),
                    Some("ALL" | "SYS_ADMIN" | "SYS_PTRACE" | "NET_ADMIN")
                ) {
                    add(
                        out,
                        file,
                        loc.clone(),
                        "DG-C004",
                        Severity::High,
                        "Powerful capability added",
                        &format!(
                            "Capability {} is explicitly granted.",
                            cap.as_str().unwrap_or("")
                        ),
                        "Remove unnecessary capabilities and apply least privilege.",
                    );
                }
            }
        }
        if let Some(ports) = service.get("ports").and_then(Value::as_sequence) {
            for port in ports {
                let exposed = if let Some(s) = port.as_str() {
                    if s.contains('$') {
                        false
                    } else {
                        let count = s.matches(':').count();
                        count == 1 || s.starts_with("0.0.0.0:") || s.starts_with("[::]:")
                    }
                } else if port.is_number() {
                    false
                } else {
                    port.get("published").is_some()
                        && matches!(
                            port.get("host_ip").and_then(Value::as_str),
                            None | Some("0.0.0.0" | "::")
                        )
                };
                if exposed {
                    add(out, file, loc.clone(), "DG-C005", Severity::Medium, "Port published on all interfaces", "The published port may be reachable from external networks, depending on host firewall settings.", "Bind to localhost or a specific interface when external access is unnecessary.");
                }
            }
        }
        let user = service.get("user");
        if user
            .and_then(Value::as_str)
            .map(|s| matches!(s.split(':').next(), Some("root" | "0")))
            .unwrap_or(false)
            || user.and_then(Value::as_i64) == Some(0)
        {
            add(
                out,
                file,
                loc,
                "DG-C006",
                Severity::High,
                "Service explicitly uses root",
                "The Compose user setting selects root.",
                "Run with a suitable non-root user.",
            );
        }
    }
    Ok(())
}
