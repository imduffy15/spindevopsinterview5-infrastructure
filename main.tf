resource "random_string" "suffix" {
  length  = 8
  special = false
}

locals {
  prefix          = "spindevopsinterview5"
  aws_region      = "us-west-2"
  db_notejam_name = "notejam"
}

provider "aws" {
  region = local.aws_region
}

data "aws_availability_zones" "available" {
}

# NETWORKING

# VPC
# private networks unused, may be introduced time depending, not wanting to
# deal with the complexities and costs (NAT Gateways) they introduce for now.

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 2.47"

  name             = "${local.prefix}-vpc-${random_string.suffix.result}"
  cidr             = "10.0.0.0/16"
  azs              = data.aws_availability_zones.available.names
  private_subnets  = []
  database_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets   = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway = false

  create_database_subnet_group           = true
  create_database_subnet_route_table     = true
  create_database_internet_gateway_route = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.prefix}-eks-${random_string.suffix.result}" = "shared"
    "kubernetes.io/role/elb"                                                   = "1"
  }
}

# Default security group, everything has access to each other

resource "aws_security_group" "default" {
  name        = "${local.prefix}-default-${random_string.suffix.result}"
  description = "Default security group for ${local.prefix}-eks-${random_string.suffix.result}"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = -1
    self      = true
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# EKS

module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "${local.prefix}-eks-${random_string.suffix.result}"
  cluster_version = "1.17"
  subnets         = module.vpc.public_subnets

  vpc_id = module.vpc.vpc_id

  worker_groups = [
    {
      name                 = "${local.prefix}-default-node-pool-${random_string.suffix.result}"
      instance_type        = "t3.medium"
      asg_desired_capacity = 3
    }
  ]

  worker_additional_security_group_ids = [aws_security_group.default.id]
}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

resource "local_file" "kubeconfig" {
  filename = "${path.module}/generated_configs/kubeconfig"
  content = templatefile("${path.module}/templates/kubeconfig.yaml.tpl", {
    endpoint            = data.aws_eks_cluster.cluster.endpoint
    cluster_auth_base64 = data.aws_eks_cluster.cluster.certificate_authority[0].data
    cluster_arn         = data.aws_eks_cluster.cluster.arn
    cluster_name        = data.aws_eks_cluster.cluster.id
    region              = local.aws_region
  })
  file_permission = 0600
}

# Helm

terraform {
  required_providers {
    helmfile = {
      source = "mumoshu/helmfile"
    }
  }
}

provider "helmfile" {}

resource "helmfile_release_set" "services" {
  helm_binary = "helm3"
  working_directory = path.module
  kubeconfig = "${path.module}/generated_configs/kubeconfig"
  depends_on = [
    local_file.kubeconfig
  ]
}

# DATABASE

resource "random_string" "db_password" {
  length  = 24
  special = false
}

resource "aws_db_instance" "notejam_db" {
  allocated_storage    = 10
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7.33"
  instance_class       = "db.t3.micro"
  db_subnet_group_name = module.vpc.database_subnet_group_name
  identifier           = "${local.prefix}-rds-${random_string.suffix.result}"
  skip_final_snapshot  = true

  vpc_security_group_ids = [
    aws_security_group.default.id
  ]

  name                = local.db_notejam_name
  username            = local.db_notejam_name
  password            = random_string.db_password.result
  publicly_accessible = true
}

resource "local_file" "dbconfig" {
  filename = "${path.module}/generated_configs/application.yaml"
  content = templatefile("${path.module}/templates/spring-db-config.yaml.tpl", {
    endpoint    = aws_db_instance.notejam_db.endpoint
    db_name     = aws_db_instance.notejam_db.endpoint
    db_password = random_string.db_password.result
  })
  file_permission = 0600
}

# KMS Key

resource "aws_kms_key" "default" {
  description             = "${local.prefix} key for encrypting stack secrets"
  deletion_window_in_days = 7
}

resource "local_file" "sopsconfig" {
  filename = "${path.module}/generated_configs/.sops.yaml"
  content = templatefile("${path.module}/templates/sops-config.yaml.tpl", {
    arn = aws_kms_key.default.arn
  })
  file_permission = 0600
}
