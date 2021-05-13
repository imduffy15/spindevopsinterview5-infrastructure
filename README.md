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
 - 
