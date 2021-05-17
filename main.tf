terraform {
  backend "s3" {
    bucket = "spindevopsinterview5-terraform-states"
    key    = "infrastructure"
    region = "us-west-2"
  }
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

  name             = "${local.prefix}-vpc"
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
    "kubernetes.io/cluster/${local.prefix}-eks" = "shared"
    "kubernetes.io/role/elb"                    = "1"
  }
}

# Default security group, everything has access to each other

resource "aws_security_group" "default" {
  name        = "${local.prefix}-default"
  description = "Default security group for ${local.prefix}-eks"
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
  cluster_name    = "${local.prefix}-eks"
  cluster_version = "1.17"
  subnets         = module.vpc.public_subnets

  vpc_id = module.vpc.vpc_id

  worker_groups = [
    {
      name                 = "${local.prefix}-default-node-pool"
      instance_type        = "t3.medium"
      asg_desired_capacity = 3
      bootstrap_extra_args = "--enable-docker-bridge true"
    }
  ]

  worker_additional_security_group_ids = [aws_security_group.default.id]
  write_kubeconfig                     = false
  enable_irsa                          = true
  cluster_log_retention_in_days        = 7
  cluster_enabled_log_types            = ["api", "audit", "authenticator"]
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

data "aws_iam_policy_document" "fluentd" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = format("%s:sub", replace(module.eks.cluster_oidc_issuer_url, "https://", ""))
      values   = ["system:serviceaccount:kube-system:logging-infrastructure-fluentd"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "fluentd" {
  name               = "${local.prefix}-fluentd"
  assume_role_policy = data.aws_iam_policy_document.fluentd.json
}

data "aws_iam_policy_document" "fluentd-policy" {
  statement {
    effect = "Allow"

    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogGroup",
      "logs:PutRetentionPolicy",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "fluentd" {
  name   = "${local.prefix}-fluentd"
  role   = aws_iam_role.fluentd.id
  policy = data.aws_iam_policy_document.fluentd-policy.json
}

# data "aws_iam_policy_document" "alb" {
#   statement {
#     actions = ["sts:AssumeRoleWithWebIdentity"]
#     effect  = "Allow"

#     condition {
#       test     = "StringEquals"
#       variable = format("%s:sub", replace(module.eks.cluster_oidc_issuer_url, "https://", ""))
#       values   = ["system:serviceaccount:kube-system:aws-alb-ingress"]
#     }

#     principals {
#       identifiers = [module.eks.oidc_provider_arn]
#       type        = "Federated"
#     }
#   }
# }

# resource "aws_iam_role" "alb" {
#   name               = "${local.prefix}-alb"
#   assume_role_policy = data.aws_iam_policy_document.alb.json
# }

# data "aws_iam_policy_document" "alb-policy" {
#   statement {
#     actions = [
#       "acm:DescribeCertificate",
#       "acm:ListCertificates",
#       "acm:GetCertificate",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "ec2:AuthorizeSecurityGroupIngress",
#       "ec2:CreateSecurityGroup",
#       "ec2:CreateTags",
#       "ec2:DeleteTags",
#       "ec2:DeleteSecurityGroup",
#       "ec2:DescribeAccountAttributes",
#       "ec2:DescribeAddresses",
#       "ec2:DescribeInstances",
#       "ec2:DescribeInstanceStatus",
#       "ec2:DescribeInternetGateways",
#       "ec2:DescribeNetworkInterfaces",
#       "ec2:DescribeSecurityGroups",
#       "ec2:DescribeSubnets",
#       "ec2:DescribeTags",
#       "ec2:DescribeVpcs",
#       "ec2:ModifyInstanceAttribute",
#       "ec2:ModifyNetworkInterfaceAttribute",
#       "ec2:RevokeSecurityGroupIngress",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "elasticloadbalancing:AddListenerCertificates",
#       "elasticloadbalancing:AddTags",
#       "elasticloadbalancing:CreateListener",
#       "elasticloadbalancing:CreateLoadBalancer",
#       "elasticloadbalancing:CreateRule",
#       "elasticloadbalancing:CreateTargetGroup",
#       "elasticloadbalancing:DeleteListener",
#       "elasticloadbalancing:DeleteLoadBalancer",
#       "elasticloadbalancing:DeleteRule",
#       "elasticloadbalancing:DeleteTargetGroup",
#       "elasticloadbalancing:DeregisterTargets",
#       "elasticloadbalancing:DescribeListenerCertificates",
#       "elasticloadbalancing:DescribeListeners",
#       "elasticloadbalancing:DescribeLoadBalancers",
#       "elasticloadbalancing:DescribeLoadBalancerAttributes",
#       "elasticloadbalancing:DescribeRules",
#       "elasticloadbalancing:DescribeSSLPolicies",
#       "elasticloadbalancing:DescribeTags",
#       "elasticloadbalancing:DescribeTargetGroups",
#       "elasticloadbalancing:DescribeTargetGroupAttributes",
#       "elasticloadbalancing:DescribeTargetHealth",
#       "elasticloadbalancing:ModifyListener",
#       "elasticloadbalancing:ModifyLoadBalancerAttributes",
#       "elasticloadbalancing:ModifyRule",
#       "elasticloadbalancing:ModifyTargetGroup",
#       "elasticloadbalancing:ModifyTargetGroupAttributes",
#       "elasticloadbalancing:RegisterTargets",
#       "elasticloadbalancing:RemoveListenerCertificates",
#       "elasticloadbalancing:RemoveTags",
#       "elasticloadbalancing:SetIpAddressType",
#       "elasticloadbalancing:SetSecurityGroups",
#       "elasticloadbalancing:SetSubnets",
#       "elasticloadbalancing:SetWebACL",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "iam:CreateServiceLinkedRole",
#       "iam:GetServerCertificate",
#       "iam:ListServerCertificates",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "cognito-idp:DescribeUserPoolClient",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "tag:GetResources",
#       "tag:TagResources",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "waf:GetWebACL",
#       "waf-regional:GetWebACLForResource",
#       "waf-regional:GetWebACL",
#       "waf-regional:AssociateWebACL",
#       "waf-regional:DisassociateWebACL",
#     ]

#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "wafv2:GetWebACL",
#       "wafv2:GetWebACLForResource",
#       "wafv2:AssociateWebACL",
#       "wafv2:DisassociateWebACL"
#     ]
#     resources = ["*"]
#   }

#   statement {
#     actions = [
#       "shield:DescribeProtection",
#       "shield:GetSubscriptionState",
#       "shield:DeleteProtection",
#       "shield:CreateProtection",
#       "shield:DescribeSubscription",
#       "shield:ListProtections"
#     ]
#     resources = ["*"]
#   }
# }

# resource "aws_iam_role_policy" "alb" {
#   name   = "${local.prefix}-alb"
#   role   = aws_iam_role.alb.id
#   policy = data.aws_iam_policy_document.alb-policy.json
# }


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
  helm_binary       = "helm3"
  working_directory = path.module
  kubeconfig        = "${path.module}/generated_configs/kubeconfig"
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
  identifier           = "${local.prefix}-rds"
  skip_final_snapshot  = true

  multi_az = true

  backup_retention_period = 14

  vpc_security_group_ids = [
    aws_security_group.default.id
  ]

  name                = local.db_notejam_name
  username            = local.db_notejam_name
  password            = random_string.db_password.result
}

resource "local_file" "dbconfig" {
  filename = "${path.module}/generated_configs/application.yaml"
  content = templatefile("${path.module}/templates/spring-db-config.yaml.tpl", {
    endpoint    = aws_db_instance.notejam_db.endpoint
    db_name     = local.db_notejam_name
    db_password = random_string.db_password.result
  })
  file_permission = 0600
}

# KMS Key

resource "aws_kms_key" "notejam" {
  description             = "${local.prefix} key for encrypting notejam secrets"
  deletion_window_in_days = 7
}

resource "local_file" "sopsconfig" {
  filename = "${path.module}/generated_configs/notejam-sops.yaml"
  content = templatefile("${path.module}/templates/sops-config.yaml.tpl", {
    kms_arn = aws_kms_key.notejam.arn
  })
  file_permission = 0600
}

resource "aws_ecr_repository" "registry" {
  name = "${local.prefix}-notejam"
  image_scanning_configuration {
    scan_on_push = false
  }
}

# CI

resource "aws_iam_user" "ci_user" {
  name = "${local.prefix}-notejam-ci-user"
}

resource "aws_iam_access_key" "ci_user" {
  user = aws_iam_user.ci_user.name
}

resource "local_file" "ci_user" {
  filename        = "${path.module}/generated_configs/ci-aws-creds.txt"
  content         = "${aws_iam_access_key.ci_user.id}\n${aws_iam_access_key.ci_user.secret}\n"
  file_permission = 0600
}

resource "aws_iam_user_policy" "ci_user" {
  name = "${local.prefix}-notejam-ci-user"
  user = aws_iam_user.ci_user.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchGetImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:PutImage"
            ],
            "Resource": "${aws_ecr_repository.registry.arn}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": "${aws_kms_key.notejam.arn}"
        }
    ]
}
EOF
}

# SMTP

resource "aws_iam_user" "smtp_user" {
  name = "${local.prefix}-notejam-smtp-user"
}

resource "aws_iam_access_key" "smtp_user" {
  user = aws_iam_user.smtp_user.name
}

resource "local_file" "smtp_user" {
  filename        = "${path.module}/generated_configs/smtp-creds.txt"
  content         = "${aws_iam_access_key.smtp_user.id}\n${aws_iam_access_key.smtp_user.ses_smtp_password_v4}\n"
  file_permission = 0600
}

resource "aws_iam_user_policy" "smtp-user" {
  name = "${local.prefix}-notejam-smtp-user"
  user = aws_iam_user.smtp_user.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
