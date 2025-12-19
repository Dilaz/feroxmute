//! Docker image build context creation

use crate::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tar::Builder;

/// Find the docker directory containing the Dockerfile
///
/// # Errors
///
/// Returns an error if:
/// - The Dockerfile cannot be found in any of the checked locations
/// - IO operations fail when checking paths
pub fn find_docker_dir() -> Result<PathBuf> {
    // First check ./docker/Dockerfile relative to CWD
    let cwd_docker = PathBuf::from("./docker");
    if cwd_docker.join("Dockerfile").exists() {
        return Ok(cwd_docker);
    }

    // Then check ../../docker/Dockerfile relative to executable (for development builds)
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_parent) = exe.parent() {
            let dev_docker = exe_parent.join("../../docker");
            if dev_docker.join("Dockerfile").exists() {
                return Ok(dev_docker
                    .canonicalize()
                    .unwrap_or(dev_docker));
            }
        }
    }

    // Finally check FEROXMUTE_DOCKER_DIR environment variable
    if let Ok(env_docker) = env::var("FEROXMUTE_DOCKER_DIR") {
        let env_path = PathBuf::from(env_docker);
        if env_path.join("Dockerfile").exists() {
            return Ok(env_path);
        }
    }

    Err(crate::Error::Config(
        "Could not find docker directory with Dockerfile. Checked: ./docker/, \
         ../../docker/ (relative to executable), and FEROXMUTE_DOCKER_DIR environment variable"
            .to_string(),
    ))
}

/// Create a tar archive build context from the docker directory
///
/// # Errors
///
/// Returns an error if:
/// - Reading the docker directory fails
/// - Creating the tar archive fails
/// - IO operations fail
pub fn create_build_context(docker_dir: &Path) -> Result<Vec<u8>> {
    let mut archive_data = Vec::new();
    {
        let mut archive = Builder::new(&mut archive_data);

        // Read all entries in the docker directory
        for entry_result in fs::read_dir(docker_dir)? {
            let entry = entry_result?;
            let path = entry.path();

            // Skip directories and hidden files (like .dockerignore)
            if path.is_dir() {
                continue;
            }

            // Get the file name
            let file_name = path
                .file_name()
                .ok_or_else(|| {
                    crate::Error::Config(format!(
                        "Invalid file name in docker directory: {}",
                        path.display()
                    ))
                })?;

            // Add file to archive with just the filename (no directory prefix)
            let mut file = fs::File::open(&path)?;
            archive.append_file(file_name, &mut file)?;
        }

        archive.finish()?;
    }

    Ok(archive_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tar::Archive;
    use tempfile::TempDir;

    #[test]
    fn test_find_docker_dir_cwd() {
        // Save the current directory
        let original_dir = env::current_dir().expect("Failed to get current dir");

        // Change to the workspace root (assuming tests are run from workspace)
        // If we can find the workspace root by looking for Cargo.toml with [workspace]
        let workspace_root = original_dir
            .ancestors()
            .find(|p| p.join("Cargo.toml").exists() && p.join("docker").exists())
            .expect("Could not find workspace root");

        env::set_current_dir(workspace_root).expect("Failed to change dir");

        let result = find_docker_dir();

        // Restore original directory
        env::set_current_dir(original_dir).expect("Failed to restore dir");

        assert!(result.is_ok(), "Should find docker dir: {:?}", result);
    }

    #[test]
    fn test_create_build_context() {
        // Create a temporary directory with a test Dockerfile
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dockerfile_path = temp_dir.path().join("Dockerfile");
        fs::write(&dockerfile_path, "FROM alpine:latest\n").expect("Failed to write Dockerfile");

        // Create build context
        let result = create_build_context(temp_dir.path());
        assert!(result.is_ok(), "Should create build context: {:?}", result);

        // Verify the tar archive contains the Dockerfile
        let archive_data = result.expect("Should have archive data");
        let mut archive = Archive::new(&archive_data[..]);

        let mut found_dockerfile = false;
        for entry_result in archive.entries().expect("Should read archive entries") {
            let entry = entry_result.expect("Should read entry");
            let path = entry.path().expect("Should have path");
            if path.to_str() == Some("Dockerfile") {
                found_dockerfile = true;
                let mut contents = String::new();
                entry
                    .take(1024)
                    .read_to_string(&mut contents)
                    .expect("Should read Dockerfile");
                assert_eq!(contents, "FROM alpine:latest\n");
            }
        }

        assert!(found_dockerfile, "Archive should contain Dockerfile");
    }
}
