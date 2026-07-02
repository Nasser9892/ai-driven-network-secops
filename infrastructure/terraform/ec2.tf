data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "target" {
  ami                         = "ami-0111f46977d33b84b"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.workloads.id]
  key_name                    = var.key_pair_name
  tags = {
    Name    = "${var.project_name}-target"
    Role    = "workload"
    Project = var.project_name
  }
}

resource "aws_instance" "zeek" {
  ami                         = "ami-0111f46977d33b84b"
  instance_type               = "t3.large"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.zeek.id]
  key_name                    = var.key_pair_name
  tags = {
    Name    = "${var.project_name}-zeek"
    Role    = "security"
    Project = var.project_name
  }
}

resource "aws_instance" "detection" {
  ami                         = "ami-0111f46977d33b84b"
  instance_type               = "t3.large"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.detection.id]
  key_name                    = var.key_pair_name
  tags = {
    Name    = "${var.project_name}-detection"
    Role    = "detection"
    Project = var.project_name
  }
}

resource "aws_instance" "management" {
  ami                         = "ami-0111f46977d33b84b"
  instance_type               = "t3.xlarge"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.management.id]
  key_name                    = var.key_pair_name
  tags = {
    Name    = "${var.project_name}-management"
    Role    = "management"
    Project = var.project_name
  }
}

resource "aws_instance" "secops_dashboard" {
  ami                    = "ami-0111f46977d33b84b"
  instance_type          = "t3.medium"
  subnet_id              = "subnet-023e50f4841e32e8c"
  vpc_security_group_ids = [aws_security_group.dashboard_sg.id]
  key_name               = "secops-key"

  tags = {
    Name = "secops-dashboard"
  }
}
