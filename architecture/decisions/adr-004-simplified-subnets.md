# ADR-004: Simplified Subnet Structure for Portfolio Deployment

## Status
Accepted

## Context
The architecture document (v2.0) defines 6 subnets for strict layer isolation:
- Public, Workloads, Security, AI, Management, Data

In a production environment this is the correct approach.
However, for this portfolio deployment on AWS Free Tier ($200 credit):
- Each private subnet requires a NAT Gateway (~$32/month each)
- 5 NAT Gateways = ~$160/month, consuming the entire credit in one month
- Security Groups already provide service-level isolation between EC2s

## Decision
Use 2 subnets instead of 6:
- **Public Subnet (10.0.1.0/24):** All EC2s with direct Public IP
- **Private Subnet (10.0.2.0/24):** Zeek only (no public access needed)

Security Group rules enforce the same isolation model as the 6-subnet design.

## Consequences
- Cost stays within $200 credit
- Same security isolation via Security Groups
- Production deployment would revert to the 6-subnet architecture
