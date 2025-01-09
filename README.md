# Cloudflare-Terraform-Rule-Migrator
Automated Migration of Deprecated Rate-Limiting Rules

# Project Description
This project provides a **Cloudflare Rule Migrator**, a tool to automate the migration of deprecated Cloudflare `cloudflare_rate_limit` rules written in Terraform into the updated `cloudflare_ruleset` format.
- A Python-based Flask web application where users can paste their deprecated rules.
- Automated parsing and dynamic conversion of the rules into the updated format using Jinja2 templates.
- Proper handling of key configurations like thresholds, timeouts, zone names, and path patterns.

This tool simplifies and accelerates the migration process, ensuring compliance with Cloudflare’s updated configuration standards.

# Cloudflare Rule Migrator

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Terraform](https://img.shields.io/badge/Terraform-Supported-brightgreen)

## Prerequisites

Make sure you have the following installed:
- Python 3.9+
- Flask (`pip3 install flask`)
- Jinja2 (`pip3 install jinja2`)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/EmreOvunc/Cloudflare-Rule-Migrator.git
    cd cloudflare-rule-migrator
    ```

2. Install dependencies:
    ```bash
    pip3 install -r requirements.txt
    ```

#### To Dockerize it, follow these steps:
- In the `app.py`, update the app.run command to bind to all interfaces (0.0.0.0) so that it works inside the Docker container:
```
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```
- Run the following command to build your Docker image:
```
docker build -t cloudflare-rule-migrator .
```
- Run the container:
```
docker run -d -p 5000:5000 --name rule-migrator cloudflare-rule-migrator
```

## Usage
1. Run the Flask application:
    ```bash
    python3 app.py
    ```

2. Open your browser and navigate to:
    ```
    http://127.0.0.1:5000/
    ```

3. Paste your deprecated `cloudflare_rate_limit` rule into the input form and click "Convert Rule."

4. Copy the migrated `cloudflare_ruleset` configuration using the "Copy to Clipboard" button.

## Example Input and Output

### Deprecated Rule (Input)

```hcl
resource "cloudflare_rate_limit" "test-login-endpoint" {
  description = "Login rate limiting"
  zone_id     = var.cloudflare_domains_map["example.net"]
  threshold   = 10
  period      = 60

  match {
    request {
      methods     = ["POST"]
      url_pattern = "test*.example.net/api*/endpoint"
    }
  }

  action {
    mode    = "simulate"
    timeout = 600
  }
}
```

### Migrated Rule (Output)
```hcl
resource "cloudflare_ruleset" "zone_rate_limits" {
  description = "Zone level Rate Limit - example.net"
  kind        = "zone"
  name        = "Zone level Rate Limit - example.net"
  phase       = "http_ratelimit"
  zone_id     = local.zone_id

  rules {
    action      = "log"
    description = "Login rate limiting"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 10
      mitigation_timeout  = 600
      requests_to_origin  = false
    }

    expression = <<EOF
    (
      http.host matches "test*.example.net"
      and http.request.uri.path matches "/api*/endpoint"
      and http.request.method eq "POST"
    )
    EOF
  }
}
```
