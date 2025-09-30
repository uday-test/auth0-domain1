variable "auth0_domain" {
  description = "Auth0 tenant domain"
  type        = string
}

variable "auth0_client_id" {
  description = "Auth0 M2M Client ID for Terraform"
  type        = string
  sensitive   = true
}

variable "auth0_client_secret" {
  description = "Auth0 M2M Client Secret for Terraform"
  type        = string
  sensitive   = true
}