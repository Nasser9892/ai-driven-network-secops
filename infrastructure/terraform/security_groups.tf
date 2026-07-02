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
  lifecycle {
    ignore_changes = [ingress]
  }
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

resource "aws_security_group" "dashboard_sg" {
  lifecycle {
    ignore_changes = [ingress]
  }
  name        = "secops-dashboard-sg"
  description = "Security group for SOC Dashboard"
  vpc_id      = "vpc-0455a10988fec19f5"

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["202.7.245.124/32"]
  }

  ingress {
    description = "Dashboard Web UI"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["202.7.245.124/32"]
  }

  ingress {
    description = "FastAPI backend"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["202.7.245.124/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "secops-dashboard-sg"
  }
}

resource "aws_security_group_rule" "detection_wazuh_agent" {
  type              = "ingress"
  from_port         = 1514
  to_port           = 1514
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.detection.id
}

resource "aws_security_group_rule" "detection_wazuh_reg" {
  type              = "ingress"
  from_port         = 1515
  to_port           = 1515
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.detection.id
}
resource "aws_security_group" "zeek" {
  name        = "${var.project_name}-zeek-sg"
  description = "Zeek engine - receives mirrored traffic, no direct inbound"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from management layer only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Send logs to ML engine and Wazuh"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.1.0/24"]
  }

  tags = {
    Name    = "${var.project_name}-zeek-sg"
    Project = var.project_name
  }
}

resource "aws_security_group_rule" "management_ollama" {
  type              = "ingress"
  from_port         = 11434
  to_port           = 11434
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.management.id
}
