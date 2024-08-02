packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "~> 1"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# variable to select ubuntu AMI
variable "use_ubuntu" {
  type    = bool
  default = true
}

# variable to select redhat AMI
variable "use_redhat" {
  type    = bool
  default = false
}

variable "ami_tag" {
  type    = string
  default = "default_tag"
}

# ubuntu source block
source "amazon-ebs" "ubuntu" {
  ami_name      = "packer-example-ubuntu-{{timestamp}}"
  instance_type = "t3.micro"
  region        = var.aws_region
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"] # Canonical
  }
  ssh_username = "ubuntu"
  tags = {
    "Name"        = "Af-xtern-A"
    "Environment" = "var.ami_tag"
    "OS_Version"  = "Ubuntu 20.04"
    "Release"     = "Latest"
    "Created-by"  = "Packer"
  }
}

# redhat source block
source "amazon-ebs" "redhat" {
  ami_name      = "packer-example-redhat-{{timestamp}}"
  instance_type = "t3.micro"
  region        = var.aws_region
  source_ami_filter {
    filters = {
      name                = "RHEL-8.4.0_HVM-*-x86_64-*-Hourly2-GP2"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["309956199498"] # Red Hat
  }
  ssh_username = "ec2-user"
  tags = {
    "Name"        = "Af-xtern-A"
    "Environment" = "var.ami_tag"
    "OS_Version"  = "RHEL 8.4"
    "Release"     = "Latest"
    "Created-by"  = "Packer"
  }
}

build {
  sources = var.use_ubuntu ? ["source.amazon-ebs.ubuntu"] : var.use_redhat ? ["source.amazon-ebs.redhat"] : []

  # I added this part incase you intend to test/run from your local system NoT from a pipeline.
  # To do this kindly uncomment the "file provision" block below and add "/tmp" to "shell provision" block below.
  # e.g /tmp/packer-scripts/001-critical-standards.sh, /tmp/packer-scripts/002-critical-standards.sh

  provisioner "file" {
     source      = "packer-scripts"
     destination = "/tmp"
  }

  # Using Hcl2 concat function and variable shell provisioning across ubuntu and redhat Linux distros
  provisioner "shell" {
    inline = concat(
      var.use_ubuntu ? ["sudo apt update -y"] : [],
      var.use_redhat ? ["sudo yum update -y"] : [],
      [
        "sudo bash /tmp/packer-scripts/001-critical-standards.sh",
        "sudo bash /tmp/packer-scripts/002-critical-standards.sh"
      ]
    )
  }
 
}
