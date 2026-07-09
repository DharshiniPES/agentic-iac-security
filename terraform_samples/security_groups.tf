# Safe Security Group (HTTP only)

resource "aws_security_group" "web_sg" {

  name = "web-security-group"

  ingress {

    from_port   = 80

    to_port     = 80

    protocol    = "tcp"

    cidr_blocks = ["0.0.0.0/0"]

  }

}

# Unsafe Security Group (SSH exposed)

resource "aws_security_group" "ssh_sg" {

  name = "ssh-security-group"

  ingress {

    from_port   = 22

    to_port     = 22

    protocol    = "tcp"

    cidr_blocks = ["0.0.0.0/0"]

  }

}

# Internal Database

resource "aws_security_group" "db_sg" {

  name = "database-security-group"

  ingress {

    from_port   = 3306

    to_port     = 3306

    protocol    = "tcp"

    cidr_blocks = ["10.0.0.0/16"]

  }

}