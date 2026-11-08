use crate::model::{Finding, Severity};
use serde::Serialize;
use serde_json::Value;
use std::process::Command;

pub const RULES: &[(&str, &str)] = &[
    ("DG-R001", "Privileged container"),
    ("DG-R002", "Host namespace"),
    ("DG-R003", "Docker socket or sensitive host mount"),
    ("DG-R004", "Powerful capability"),
    ("DG-R005", "Port published on all interfaces"),
    ("DG-R006", "Docker default user is root or unspecified"),
    ("DG-R007", "Writable container root filesystem"),
    ("DG-R008", "No memory limit"),
    ("DG-R009", "No CPU limit"),
];

#[derive(Serialize)]
pub struct RuntimeReport {
    pub scanned_containers: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

fn docker(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("Unable to start Docker CLI: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Docker command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("Docker returned invalid UTF-8: {e}"))
}

pub fn scan() -> RuntimeReport {
    let mut report = RuntimeReport {
        scanned_containers: 0,
        findings: Vec::new(),
        errors: Vec::new(),
    };
    let ids = match docker(&["ps", "--no-trunc", "--quiet"]) {
        Ok(ids) => ids,
        Err(e) => {
            report.errors.push(e);
            return report;
        }
    };
    for id in ids.lines().filter(|s| !s.is_empty()) {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            report
                .errors
                .push("Docker returned an invalid container ID".into());
            continue;
        }
        let result = docker(&["container", "inspect", id]).and_then(|s| {
            let value: Value = serde_json::from_str(&s)
                .map_err(|e| format!("Invalid Docker inspect JSON: {e}"))?;
            let container = value
                .as_array()
                .and_then(|a| a.first())
                .ok_or("Docker inspect returned no container")?;
            inspect(container, &mut report.findings)
        });
        match result {
            Ok(()) => report.scanned_containers += 1,
            Err(e) => report.errors.push(format!("Container {}: {e}", &id[..12])),
        }
    }
    report
}
fn add(
    out: &mut Vec<Finding>,
    name: &str,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: String,
    recommendation: &'static str,
) {
    out.push(Finding {
        rule_id: id,
        severity,
        title,
        file: format!("container: {name}"),
        location: None,
        detail,
        recommendation,
    });
}
fn inspect(c: &Value, out: &mut Vec<Finding>) -> Result<(), String> {
    let host = c
        .get("HostConfig")
        .filter(|v| v.is_object())
        .ok_or("Missing HostConfig")?;
    let config = c
        .get("Config")
        .filter(|v| v.is_object())
        .ok_or("Missing Config")?;
    let name = c
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>")
        .trim_start_matches('/');
    if host.get("Privileged").and_then(Value::as_bool) == Some(true) {
        add(
            out,
            name,
            "DG-R001",
            Severity::Critical,
            "Privileged container",
            "The container has broad host privileges.".into(),
            "Disable privileged mode and grant only required permissions.",
        );
    }
    for key in ["NetworkMode", "PidMode", "IpcMode"] {
        if host.get(key).and_then(Value::as_str) == Some("host") {
            add(
                out,
                name,
                "DG-R002",
                Severity::High,
                "Host namespace shared",
                format!("{key} is set to host."),
                "Use an isolated namespace where possible.",
            );
        }
    }
    if let Some(mounts) = c.get("Mounts").and_then(Value::as_array) {
        for mount in mounts {
            if mount.get("Type").and_then(Value::as_str) != Some("bind") {
                continue;
            }
            let source = mount.get("Source").and_then(Value::as_str).unwrap_or("");
            let sensitive = matches!(
                source,
                "/" | "/etc" | "/proc" | "/sys" | "/var/run/docker.sock" | "/run/docker.sock"
            );
            if sensitive {
                let socket = source.ends_with("docker.sock");
                add(
                    out,
                    name,
                    "DG-R003",
                    if socket {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    "Sensitive host bind mount",
                    format!(
                        "Host path {source} is mounted; read-only: {}.",
                        mount.get("RW").and_then(Value::as_bool) == Some(false)
                    ),
                    "Remove the mount or restrict access to the minimum required.",
                );
            }
        }
    }
    if let Some(caps) = host.get("CapAdd").and_then(Value::as_array) {
        for cap in caps.iter().filter_map(Value::as_str) {
            let cap = cap.strip_prefix("CAP_").unwrap_or(cap);
            if matches!(cap, "ALL" | "SYS_ADMIN" | "SYS_PTRACE" | "NET_ADMIN") {
                add(
                    out,
                    name,
                    "DG-R004",
                    Severity::High,
                    "Powerful capability added",
                    format!("{cap} is explicitly granted."),
                    "Remove unnecessary capabilities.",
                );
            }
        }
    }
    if let Some(ports) = c
        .pointer("/NetworkSettings/Ports")
        .and_then(Value::as_object)
    {
        for (port, bindings) in ports {
            if let Some(bindings) = bindings.as_array() {
                for binding in bindings {
                    let ip = binding.get("HostIp").and_then(Value::as_str).unwrap_or("");
                    if matches!(ip, "" | "0.0.0.0" | "::") {
                        add(out,name,"DG-R005",Severity::Medium,"Port published on all interfaces",format!("Container port {port} is published on {ip}; reachability depends on network and firewall settings."),"Bind to a specific interface when external access is unnecessary.");
                    }
                }
            }
        }
    }
    if let Some(user) = config.get("User").and_then(Value::as_str) {
        if matches!(user.split(':').next(), Some("" | "root" | "0")) {
            add(out,name,"DG-R006",Severity::Medium,"Docker default user is root or unspecified","Docker's configured startup user is root or unspecified. Entrypoints may change user; running process identities were not inspected. User namespace remapping may affect host-side identity.".into(),"Check the image and running process identities, and configure a non-root user when compatible.");
        }
    }
    if host.get("ReadonlyRootfs").and_then(Value::as_bool) == Some(false) {
        add(
            out,
            name,
            "DG-R007",
            Severity::Low,
            "Writable root filesystem",
            "The container root filesystem is writable.".into(),
            "Use a read-only root filesystem where compatible.",
        );
    }
    if host.get("Memory").and_then(Value::as_i64) == Some(0) {
        add(out,name,"DG-R008",Severity::Low,"No container memory limit","No explicit Docker memory limit is configured; host or parent cgroup limits may still apply.".into(),"Set a suitable memory limit.");
    }
    let nano = host.get("NanoCpus").and_then(Value::as_i64);
    let quota = host.get("CpuQuota").and_then(Value::as_i64);
    if nano == Some(0) && quota.is_some_and(|v| v <= 0) {
        add(out,name,"DG-R009",Severity::Low,"No container CPU quota","No explicit Docker CPU quota is configured; host or parent cgroup limits may still apply.".into(),"Set an appropriate CPU limit where needed.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn detects_risks_and_avoids_localhost_port() {
        let c = json!({"Name":"/web","Config":{"User":"0"},"HostConfig":{"Privileged":true,"NetworkMode":"host","ReadonlyRootfs":false,"Memory":0,"NanoCpus":0,"CpuQuota":0,"CapAdd":["CAP_SYS_ADMIN"]},"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","RW":true}],"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}],"81/tcp":[{"HostIp":"127.0.0.1","HostPort":"8181"}]}}});
        let mut findings = vec![];
        inspect(&c, &mut findings).unwrap();
        for (id, _) in RULES {
            assert!(findings.iter().any(|f| f.rule_id == *id), "missing {id}");
        }
        assert_eq!(
            findings.iter().filter(|f| f.rule_id == "DG-R005").count(),
            1
        );
    }
    #[test]
    fn rejects_incomplete_inspect() {
        assert!(inspect(&json!({}), &mut vec![]).is_err());
    }
}
