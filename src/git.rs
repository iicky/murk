//! Git integration helpers (merge driver setup).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// A step completed during merge driver setup.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeDriverSetupStep {
    /// `.gitattributes` already contained the merge driver entry.
    GitattributesAlreadyExists,
    /// Appended the merge driver entry to an existing `.gitattributes`.
    GitattributesAppended,
    /// Created a new `.gitattributes` file with the merge driver entry.
    GitattributesCreated,
    /// Configured `git config merge.murk.*`.
    GitConfigured,
}

/// Configure git to use murk's custom merge driver for `.murk` files.
///
/// 1. Ensures `.gitattributes` contains `*.murk merge=murk`.
/// 2. Runs `git config merge.murk.name` and `git config merge.murk.driver`.
///
/// Returns the steps that were performed.
pub fn setup_merge_driver() -> Result<Vec<MergeDriverSetupStep>, String> {
    let mut steps = Vec::new();

    // 1. Write .gitattributes entry.
    let gitattributes = Path::new(".gitattributes");
    let merge_line = "*.murk merge=murk";

    if gitattributes.exists() {
        let contents = fs::read_to_string(gitattributes)
            .map_err(|e| format!("reading .gitattributes: {e}"))?;
        if contents.contains(merge_line) {
            steps.push(MergeDriverSetupStep::GitattributesAlreadyExists);
        } else {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(gitattributes)
                .map_err(|e| format!("writing .gitattributes: {e}"))?;
            writeln!(file, "{merge_line}").map_err(|e| format!("writing .gitattributes: {e}"))?;
            steps.push(MergeDriverSetupStep::GitattributesAppended);
        }
    } else {
        fs::write(gitattributes, format!("{merge_line}\n"))
            .map_err(|e| format!("writing .gitattributes: {e}"))?;
        steps.push(MergeDriverSetupStep::GitattributesCreated);
    }

    // 2. Configure git merge driver.
    let configs = [
        ("merge.murk.name", "murk vault merge"),
        ("merge.murk.driver", "murk merge-driver %O %A %B"),
    ];
    for (key, value) in &configs {
        let status = Command::new("git")
            .args(["config", key, value])
            .status()
            .map_err(|e| format!("running git config: {e}"))?;
        if !status.success() {
            return Err(format!("git config {key} failed (are you in a git repo?)"));
        }
    }
    steps.push(MergeDriverSetupStep::GitConfigured);

    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_merge_driver_creates_gitattributes() {
        let dir = std::env::temp_dir().join("murk_test_git_setup");
        std::fs::create_dir_all(&dir).unwrap();

        // Init a git repo so git config works.
        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesCreated));
        assert!(steps.contains(&MergeDriverSetupStep::GitConfigured));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_appends_gitattributes() {
        let dir = std::env::temp_dir().join("murk_test_git_append");
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.txt text\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAppended));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.txt text"));
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_already_exists() {
        let dir = std::env::temp_dir().join("murk_test_git_exists");
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.murk merge=murk\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAlreadyExists));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
