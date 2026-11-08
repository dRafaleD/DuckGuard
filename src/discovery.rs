use std::path::{Path, PathBuf};
use walkdir::WalkDir;
pub fn kind(path: &Path) -> Option<bool> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name == "dockerfile" || name.starts_with("dockerfile.") {
        Some(true)
    } else if matches!(
        name.as_str(),
        "compose.yaml" | "compose.yml" | "docker-compose.yml" | "docker-compose.yaml"
    ) {
        Some(false)
    } else {
        None
    }
}
pub fn discover(path: &Path) -> (Vec<PathBuf>, Vec<String>) {
    if !path.exists() {
        return (
            vec![],
            vec![format!("{}: path does not exist", path.display())],
        );
    }
    if path.is_file() {
        return if kind(path).is_some() {
            (vec![path.to_owned()], vec![])
        } else {
            (
                vec![],
                vec![format!("{}: unsupported file name", path.display())],
            )
        };
    }
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !matches!(
                    e.file_name().to_str(),
                    Some(".git" | "node_modules" | "target")
                )
        })
    {
        match entry {
            Ok(e) if e.file_type().is_file() && kind(e.path()).is_some() => {
                files.push(e.into_path())
            }
            Ok(_) => {}
            Err(e) => errors.push(e.to_string()),
        }
    }
    files.sort();
    (files, errors)
}
