echo "###################### Executing 002-critical-standards.sh ##########################"
echo 'Hello, Packer!'

#!/bin/bash

# Log file location
log_file="/var/log/time_sync_setup.log"

# Logging function
log() {
  echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a $log_file
}

# Function to configure time synchronization
configure_time_sync() {
  log "Starting time synchronization setup."

  # Detect the package manager and install chrony
  if [ -f /etc/debian_version ]; then
    log "Debian-based system detected."
    pkg_mgr="apt-get"
    install_cmd="apt-get install -y chrony"
  elif [ -f /etc/redhat-release ]; then
    log "RedHat-based system detected."
    pkg_mgr="yum"
    install_cmd="yum install -y chrony"
  else
    log "Unsupported system type."
    return 1
  fi

  # Install chrony
  if $install_cmd; then
    log "chrony installed successfully."
  else
    log "Error installing chrony."
    return 1
  fi

  # Enable and start chrony service
  if systemctl enable chrony && systemctl start chrony; then
    log "chrony service enabled and started successfully."
  else
    log "Error enabling or starting chrony service."
    return 1
  fi

  # Validate time synchronization
  if chronyc tracking; then
    log "Time synchronization validated successfully."
  else
    log "Time synchronization validation failed."
    return 1
  fi

  log "Time synchronization setup completed successfully."
  return 0
}

# Function to secure kernel parameters
secure_kernel_params() {
  log "Starting kernel parameter security setup."

  # Update /etc/sysctl.conf with secure kernel parameters
  echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
  echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

  # Apply the kernel parameters immediately
  if sysctl -p; then
    log "Kernel parameters applied successfully."
  else
    log "Error applying kernel parameters."
    return 1
  fi

  # Validate the kernel parameters
  params=("net.ipv4.ip_forward" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.all.secure_redirects" "net.ipv4.conf.all.log_martians" "kernel.randomize_va_space")
  for param in "${params[@]}"; do
    if sysctl $param; then
      log "$param validated successfully."
    else
      log "Error validating $param."
      return 1
    fi
  done

  log "Kernel parameter security setup completed successfully."
  return 0
}

# Wrapper function to execute a given function and check its exit code
execute_and_check() {
  local func_name=$1
  shift
  $func_name "$@"
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log "Error: $func_name failed with exit code $exit_code."
    exit $exit_code
  fi
}

# Main script execution
execute_and_check configure_time_sync
execute_and_check secure_kernel_params


echo "#################### 002-critical-standards.sh execution completed ###################" > /var/log/002-critical-standards.log
