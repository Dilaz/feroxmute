//! Docker container management for Kali tools

use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    BuildImageOptions, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::{Docker, body_full};
use futures::StreamExt;
use hyper::body::Bytes;
use std::path::Path;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// Maximum output size in bytes (10MB)
const MAX_OUTPUT_SIZE: usize = 10_485_760;

/// Default exec timeout in seconds (10 minutes)
const EXEC_TIMEOUT_SECS: u64 = 600;

/// Container configuration
pub struct ContainerConfig {
    pub image: String,
    pub name: String,
    pub workdir: String,
    pub volumes: Vec<(String, String)>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: "feroxmute-kali".to_string(),
            name: "feroxmute-kali".to_string(),
            workdir: "/feroxmute".to_string(),
            volumes: vec![],
        }
    }
}

impl ContainerConfig {
    /// Add a source directory mount for SAST analysis (read-only)
    pub fn with_source_mount(mut self, host_path: &str) -> Self {
        let path = Path::new(host_path);
        if host_path == "/" {
            warn!("Source mount path is root '/'; this is dangerous");
        }
        if !path.is_dir() {
            warn!("Source mount path is not a directory: {}", host_path);
        }
        // Mount source code at /source in the container (read-only for safety)
        self.volumes
            .push((host_path.to_string(), "/source:ro".to_string()));
        self
    }
}

/// Docker container manager
pub struct ContainerManager {
    docker: Docker,
    config: ContainerConfig,
    container_id: Option<String>,
}

impl ContainerManager {
    /// Create a new container manager
    pub async fn new(config: ContainerConfig) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify Docker is accessible
        docker.ping().await.map_err(|e| {
            Error::Docker(bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: format!("Cannot connect to Docker: {}", e),
            })
        })?;

        Ok(Self {
            docker,
            config,
            container_id: None,
        })
    }

    /// Check if the container image exists
    pub async fn image_exists(&self) -> Result<bool> {
        match self.docker.inspect_image(&self.config.image).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Build a Docker image from the specified docker directory
    ///
    /// The `on_progress` callback is called with each line of build output.
    pub async fn build_image<F>(&self, docker_dir: &Path, on_progress: F) -> Result<()>
    where
        F: Fn(&str),
    {
        info!("Building Docker image from: {}", docker_dir.display());

        // Create tar archive build context
        let tar_bytes = super::builder::create_build_context(docker_dir)?;

        // Convert to hyper::body::Bytes
        let bytes = Bytes::from(tar_bytes);

        // Build image options
        let options = BuildImageOptions {
            dockerfile: "Dockerfile".to_string(),
            t: Some(self.config.image.clone()),
            rm: true,
            ..Default::default()
        };

        // Stream the build output
        let mut stream = self
            .docker
            .build_image(options, None, Some(body_full(bytes)));

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    // Handle different types of build output
                    if let Some(stream_msg) = info.stream {
                        on_progress(&stream_msg);
                    }
                    if let Some(error_detail) = info.error_detail {
                        let message = error_detail
                            .message
                            .unwrap_or_else(|| "Unknown build error".to_string());
                        return Err(Error::Docker(
                            bollard::errors::Error::DockerResponseServerError {
                                status_code: 500,
                                message,
                            },
                        ));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        info!("Successfully built image: {}", self.config.image);
        Ok(())
    }

    /// Start or create the container
    pub async fn start(&mut self) -> Result<()> {
        // Check if container already exists
        match self.docker.inspect_container(&self.config.name, None).await {
            Ok(info) => {
                // Check if existing mounts match required mounts
                let existing_binds = info
                    .host_config
                    .as_ref()
                    .and_then(|hc| hc.binds.as_ref())
                    .cloned()
                    .unwrap_or_default();

                let required_binds: Vec<String> = self
                    .config
                    .volumes
                    .iter()
                    .map(|(h, c)| format!("{}:{}", h, c))
                    .collect();

                // If mounts differ and we need source mount, recreate container
                let needs_recreate = !required_binds.is_empty()
                    && !required_binds.iter().all(|b| existing_binds.contains(b));

                if needs_recreate {
                    info!(
                        "Recreating container with updated mounts: {:?}",
                        required_binds
                    );
                    // Stop and remove existing container by name (not id, since it's not set yet)
                    let _ = self
                        .docker
                        .stop_container(
                            &self.config.name,
                            Some(StopContainerOptions {
                                t: Some(5),
                                ..Default::default()
                            }),
                        )
                        .await;
                    let _ = self
                        .docker
                        .remove_container(
                            &self.config.name,
                            Some(RemoveContainerOptions {
                                force: true,
                                ..Default::default()
                            }),
                        )
                        .await;
                    self.create_container().await?;
                } else {
                    self.container_id = Some(info.id.unwrap_or_default());

                    // Start if not running
                    if info.state.and_then(|s| s.running) != Some(true) {
                        info!("Starting existing container: {}", self.config.name);
                        self.docker
                            .start_container(&self.config.name, None::<StartContainerOptions>)
                            .await?;
                    }
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Create new container
                info!("Creating new container: {}", self.config.name);
                self.create_container().await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Create a new container
    async fn create_container(&mut self) -> Result<()> {
        let mut binds = vec![];
        for (host, container) in &self.config.volumes {
            binds.push(format!("{}:{}", host, container));
        }

        let host_config = HostConfig {
            binds: Some(binds),
            cap_add: Some(vec!["NET_ADMIN".to_string(), "NET_RAW".to_string()]),
            security_opt: Some(vec!["seccomp:unconfined".to_string()]),
            memory: Some(4 * 1024 * 1024 * 1024), // 4GB memory limit
            memory_swap: Some(4 * 1024 * 1024 * 1024), // No swap
            pids_limit: Some(2048),               // Process limit
            ..Default::default()
        };

        let config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            hostname: Some("feroxmute".to_string()),
            working_dir: Some(self.config.workdir.clone()),
            host_config: Some(host_config),
            tty: Some(true),
            cmd: Some(vec![
                "tail".to_string(),
                "-f".to_string(),
                "/dev/null".to_string(),
            ]),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: Some(self.config.name.clone()),
            ..Default::default()
        };

        let response = self.docker.create_container(Some(options), config).await?;
        self.container_id = Some(response.id.clone());

        self.docker
            .start_container(&self.config.name, None::<StartContainerOptions>)
            .await?;

        info!("Container started: {}", response.id);
        Ok(())
    }

    /// Execute a command in the container
    pub async fn exec(&self, cmd: Vec<&str>, workdir: Option<&str>) -> Result<ExecResult> {
        let container_id = self.container_id.as_ref().ok_or_else(|| {
            Error::Docker(bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: "Container not started".to_string(),
            })
        })?;

        debug!("Executing: {:?}", cmd);

        let exec_config = CreateExecOptions {
            cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
            working_dir: workdir.map(|s| s.to_string()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            env: Some(vec![
                "PATH=/root/.pdtm/go/bin:/root/go/bin:/root/.local/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "GOPATH=/root/go".to_string(),
            ]),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output = String::new();
        let mut stderr = String::new();
        let mut total_size: usize = 0;
        let mut truncated = false;

        if let StartExecResults::Attached {
            output: mut stream, ..
        } = self.docker.start_exec(&exec.id, None).await?
        {
            // Wrap stream reading in a timeout to prevent hanging on unresponsive commands
            let stream_result =
                tokio::time::timeout(Duration::from_secs(EXEC_TIMEOUT_SECS), async {
                    while let Some(msg) = stream.next().await {
                        match msg {
                            Ok(LogOutput::StdOut { message }) => {
                                if !truncated {
                                    let chunk = String::from_utf8_lossy(&message);
                                    total_size += chunk.len();
                                    if total_size > MAX_OUTPUT_SIZE {
                                        truncated = true;
                                        output
                                            .push_str("\n[OUTPUT TRUNCATED - exceeded 10MB limit]");
                                    } else {
                                        output.push_str(&chunk);
                                    }
                                }
                            }
                            Ok(LogOutput::StdErr { message }) => {
                                if !truncated {
                                    let chunk = String::from_utf8_lossy(&message);
                                    total_size += chunk.len();
                                    if total_size > MAX_OUTPUT_SIZE {
                                        truncated = true;
                                        stderr
                                            .push_str("\n[OUTPUT TRUNCATED - exceeded 10MB limit]");
                                    } else {
                                        stderr.push_str(&chunk);
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Error reading exec output: {}", e);
                            }
                        }
                    }
                })
                .await;

            if stream_result.is_err() {
                warn!(
                    "Command execution timed out after {} seconds",
                    EXEC_TIMEOUT_SECS
                );
                return Ok(ExecResult {
                    stdout: output,
                    stderr: format!("Command timed out after {} seconds", EXEC_TIMEOUT_SECS),
                    exit_code: -1,
                });
            }
        }

        // Get exit code
        let inspect = self.docker.inspect_exec(&exec.id).await?;
        let exit_code = inspect.exit_code.unwrap_or(-1);

        Ok(ExecResult {
            stdout: output,
            stderr,
            exit_code,
        })
    }

    /// Stop the container
    pub async fn stop(&self) -> Result<()> {
        if let Some(ref id) = self.container_id {
            info!("Stopping container: {}", id);
            self.docker
                .stop_container(
                    id,
                    Some(StopContainerOptions {
                        t: Some(10),
                        ..Default::default()
                    }),
                )
                .await?;
        }
        Ok(())
    }

    /// Remove the container
    pub async fn remove(&self) -> Result<()> {
        if let Some(ref id) = self.container_id {
            info!("Removing container: {}", id);
            self.docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await?;
        }
        Ok(())
    }
}

/// Result of executing a command
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i64,
}

impl ExecResult {
    /// Check if command succeeded
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Get combined output
    pub fn output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // Integration tests require Docker - skip in CI unless Docker is available
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_container_manager_creation() {
        let config = ContainerConfig::default();
        let manager = ContainerManager::new(config).await;
        assert!(manager.is_ok());
    }
}
