# Spin DevOps Interview 5 Infrastructure

This repository will contain all of the infrastructure related components required to complete the spin interview challenge.

This will include:

AWS Infrastructure (terraform):

 - VPC, subnets, security groups, etc.
 - KMS key for encrypting secrets
 - EKS Cluster, worker nodes, related IAM roles
 - Container registry

Software (helmfile):

 - cert-manager: provide wildcard ssl certs for the team's application(s)
 - external-dns: auto publishing of dns records for team's application(s)
 - nginx-ingress: exposes http services
 - kubed: syncing secrets across namespaces
 - ci/cd: for deploying applications, will be provided by https://woodpecker.laszlo.cloud/
 - logging-operator: enable logging of team's application(s) to cloudwatch logs
 - prometheus/grafana: enable monitoring/metrics of team's application(s)
 - shared secrets: secrets required for different components
 - oauth2 proxy: provide SSO on top of grafana/prometheus/alert manager

# Usage

It is assumed that this will be manually run by a devops engineer. Alternatively, it could be ran on some devops team owned infrastructure that is parameterised to quickly spin up new AWS accounts and infrastructure for teams.

The following utilities are required:

 - Kubectl
 - Helm
 - Helmfile
 - SOPs
 - Terraform
 - AWSCLI

---
**NOTE**

All secrets are encrypted with SOPs using an AWS KMS key, as a result, an AWS KMS key is required before creating any configuration. 

The creation of this KMS key has been automated in ./prerequisites , In a real world scenario this KMS key would be
owned by the devops team and re-used across devops owned projects.

A seperate KMS key is generated for the development team of the notejam application.

KMS key can be generated as follows:

```
$ cd prerequisites
$ terraform init
$ terraform apply
```

A sops configuration file will be outputted to ./generated_configs

---

---
**NOTE**

An S3 bucket is required for storing terraform state, this has been created manually with versioning enabled.

---

---
**NOTE**


The DNS zone for this is hosted outside of the provided AWS account. IAM access keys are provided to interact with the zone.

---