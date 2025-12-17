//! Docker container management for Kali tools

use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::Docker;
use futures::StreamExt;
use tracing::{debug, info, warn};

use crate::{Error, Result};

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
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Start or create the container
    pub async fn start(&mut self) -> Result<()> {
        // Check if container already exists
        match self.docker.inspect_container(&self.config.name, None).await {
            Ok(info) => {
                self.container_id = Some(info.id.unwrap_or_default());

                // Start if not running
                if info.state.and_then(|s| s.running) != Some(true) {
                    info!("Starting existing container: {}", self.config.name);
                    self.docker
                        .start_container(&self.config.name, None::<StartContainerOptions<String>>)
                        .await?;
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
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

        let host_config = bollard::service::HostConfig {
            binds: Some(binds),
            cap_add: Some(vec!["NET_ADMIN".to_string(), "NET_RAW".to_string()]),
            security_opt: Some(vec!["seccomp:unconfined".to_string()]),
            ..Default::default()
        };

        let config = Config {
            image: Some(self.config.image.clone()),
            hostname: Some("feroxmute".to_string()),
            working_dir: Some(self.config.workdir.clone()),
            host_config: Some(host_config),
            tty: Some(true),
            cmd: Some(vec!["tail".to_string(), "-f".to_string(), "/dev/null".to_string()]),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: &self.config.name,
            platform: None,
        };

        let response = self.docker.create_container(Some(options), config).await?;
        self.container_id = Some(response.id.clone());

        self.docker
            .start_container(&self.config.name, None::<StartContainerOptions<String>>)
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
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output = String::new();
        let mut stderr = String::new();

        if let StartExecResults::Attached { output: mut stream, .. } =
            self.docker.start_exec(&exec.id, None).await?
        {
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(bollard::container::LogOutput::StdOut { message }) => {
                        output.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(bollard::container::LogOutput::StdErr { message }) => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Error reading exec output: {}", e);
                    }
                }
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
                .stop_container(id, Some(StopContainerOptions { t: 10 }))
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
