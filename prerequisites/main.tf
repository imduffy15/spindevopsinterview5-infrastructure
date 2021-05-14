terraform {
  backend "s3" {
    bucket = "spindevopsinterview5-terraform-states"
    key    = "prerequisites"
    region = "us-west-2"
  }
}

# KMS Key

locals {
  prefix          = "spindevopsinterview5"
}

resource "aws_kms_key" "default" {
  description             = "${local.prefix} key for encrypting infrastructure secrets"
  deletion_window_in_days = 7
}

resource "local_file" "sopsconfig" {
  filename = "${path.module}/../generated_configs/infrastructure-sops.yaml"
  content = templatefile("${path.module}/../templates/sops-config.yaml.tpl", {
    kms_arn = aws_kms_key.default.arn
  })
  file_permission = 0600
}
