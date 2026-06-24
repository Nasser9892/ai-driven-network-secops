# Security Group - Target EC2s (Workloads)
resource "aws_security_group" "workloads" {
  name        = "${var.project_name}-workloads-sg"
  description = "Target EC2s - accepts inbound traffic for attack simulation"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere (demo only)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-workloads-sg"
    Project = var.project_name
  }
}

# Security Group - Zeek (passive listener)
resource "aws_security_group" "zeek" {
  name        = "${var.project_name}-zeek-sg"
  description = "Zeek engine - receives mirrored traffic via VXLAN"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere (demo only)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "VXLAN - mirrored traffic from VPC Traffic Mirroring"
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-zeek-sg"
    Project = var.project_name
  }
}

# Security Group - ML Engine + Wazuh
resource "aws_security_group" "detection" {
  name        = "${var.project_name}-detection-sg"
  description = "ML engine and Wazuh - receives logs from Zeek, sends alerts to n8n"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere (demo only)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Wazuh API"
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    description = "Wazuh dashboard"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-detection-sg"
    Project = var.project_name
  }
}

# Security Group - AI Layer (vLLM + ChromaDB)
resource "aws_security_group" "ai" {
  name        = "${var.project_name}-ai-sg"
  description = "vLLM and ChromaDB - only accessible from n8n"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere (demo only)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "vLLM API from n8n only"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-ai-sg"
    Project = var.project_name
  }
}

# Security Group - Management (n8n + SOC Dashboard)
resource "aws_security_group" "management" {
  name        = "${var.project_name}-management-sg"
  description = "n8n and SOC dashboard - accessible from internet for demo"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "n8n UI"
    from_port   = 5678
    to_port     = 5678
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SOC Dashboard"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-management-sg"
    Project = var.project_name
  }
}
