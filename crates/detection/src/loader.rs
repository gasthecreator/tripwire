use std::path::Path;
use thiserror::Error;
use tripwire_core::Signature;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("failed to read signature file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse signature file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("duplicate signature id \"{0}\" loaded from more than one file")]
    DuplicateId(String),
}

impl LoaderError {
    fn duplicate(id: &str) -> Self {
        LoaderError::DuplicateId(id.to_string())
    }
}

/// Loads every `*.yaml`/`*.yml` file in `dir` as a `Signature`. A signature
/// registry is nothing more than "every file in this directory" — adding a
/// new exploit signature is dropping a new file here, never a code change
/// (ARCHITECTURE.md §3.3). Signature ids must be unique across the whole
/// directory; a collision is a config error caught at load time, not a
/// silent overwrite at match time.
pub fn load_signatures_from_dir(dir: &Path) -> Result<Vec<Signature>, LoaderError> {
    let mut signatures = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| LoaderError::Io {
            path: dir.display().to_string(),
            source: e,
        })?
        .filter_map(|e| e.ok())
        .collect();
    // Deterministic order regardless of filesystem iteration order --
    // matters for reproducible test output and reviewable diffs of any
    // "signatures loaded" log line.
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| LoaderError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let sig: Signature = serde_yaml::from_str(&contents).map_err(|e| LoaderError::Parse {
            path: path.display().to_string(),
            source: e,
        })?;

        if !seen_ids.insert(sig.id.clone()) {
            return Err(LoaderError::duplicate(&sig.id));
        }
        signatures.push(sig);
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_sig(dir: &Path, filename: &str, id: &str) {
        let mut f = std::fs::File::create(dir.join(filename)).unwrap();
        write!(
            f,
            r#"
id: {id}
description: test signature
category: reentrancy
window_seconds: 10
conditions:
  - id: c1
    kind:
      type: reentrancy_depth
      min_depth_delta: 1
    weight: 100.0
"#
        )
        .unwrap();
    }

    #[test]
    fn loads_all_yaml_files_in_directory() {
        let dir = tempdir();
        write_sig(dir.path(), "a.yaml", "sig-a");
        write_sig(dir.path(), "b.yml", "sig-b");
        std::fs::write(dir.path().join("not-a-signature.txt"), "ignore me").unwrap();

        let sigs = load_signatures_from_dir(dir.path()).unwrap();
        assert_eq!(sigs.len(), 2);
        let ids: Vec<_> = sigs.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"sig-a"));
        assert!(ids.contains(&"sig-b"));
    }

    #[test]
    fn rejects_duplicate_signature_ids() {
        let dir = tempdir();
        write_sig(dir.path(), "a.yaml", "same-id");
        write_sig(dir.path(), "b.yaml", "same-id");

        let result = load_signatures_from_dir(dir.path());
        assert!(matches!(result, Err(LoaderError::DuplicateId(id)) if id == "same-id"));
    }

    #[test]
    fn errors_on_malformed_yaml() {
        let dir = tempdir();
        std::fs::write(
            dir.path().join("bad.yaml"),
            "not: valid: signature: yaml: [",
        )
        .unwrap();
        assert!(matches!(
            load_signatures_from_dir(dir.path()),
            Err(LoaderError::Parse { .. })
        ));
    }

    #[test]
    fn errors_on_missing_directory() {
        let missing = Path::new("/nonexistent/path/that/should/not/exist");
        assert!(matches!(
            load_signatures_from_dir(missing),
            Err(LoaderError::Io { .. })
        ));
    }

    #[test]
    fn empty_directory_yields_empty_vec() {
        let dir = tempdir();
        let sigs = load_signatures_from_dir(dir.path()).unwrap();
        assert!(sigs.is_empty());
    }

    /// Minimal temp-dir helper so this crate doesn't need a `tempfile` dev
    /// dependency just for a handful of loader tests.
    fn tempdir() -> TempDir {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tripwire-detection-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
