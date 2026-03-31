# Neural Nexus WAF Default Config

Automated WAF (Web Application Firewall) deployment script that discovers all domains in a Cloudflare account and deploys security rules to block access to sensitive paths.

## Features

- ✅ **Auto-discovers all zones** in your Cloudflare account
- ✅ **5 security rules** covering:
  - Environment files (.env, credentials, configs)
  - Git repository access (.git directories)
  - Admin panels (phpmyadmin, adminer, etc.)
  - Debug endpoints (actuator, heapdump, jolokia)
  - Database dumps and backup files (.sql)
- ✅ **Idempotent** - removes old rules before creating new ones
- ✅ **Fast** - deploys to all domains in seconds

## Prerequisites

1. **Cloudflare API Token** with permissions:
   - `Zone:Read` - to list all your zones
   - `Zone:Firewall Rules:Edit` - to create WAF rules

2. **Create your token:** https://dash.cloudflare.com/profile/api-tokens
   - Use the "Edit zone Firewall Rules" template
   - Include all zones or select specific zones

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/neuralnexus-waf-default-config.git
cd neuralnexus-waf-default-config

# Set your API token
export CLOUDFLARE_API_TOKEN="your_token_here"

# Run the deployment
node deploy-waf.js
```

## Usage

```bash
# Deploy to all active zones in your account
export CLOUDFLARE_API_TOKEN="your_api_token"
node deploy-waf.js
```

### Expected Output

```
🛡️  Cloudflare WAF Rule Deployment

📋 Fetching all zones from your account...

Found N active zones:
  • domain1.com
  • domain2.com
  • ...

🔒 Deploying WAF rules to domain1.com...
  ✅ Created: [WAF] Block environment files and credentials
  ✅ Created: [WAF] Block Git repository access
  ✅ Created: [WAF] Block admin panel access
  ✅ Created: [WAF] Block debug endpoints
  ✅ Created: [WAF] Block database dumps and backups
  ✨ Created 5 WAF rules

📊 Deployment Summary:
====================
✅ 5 rules deployed to each domain
```

## Testing

After deployment (wait 30-60 seconds), verify the rules are working:

```bash
# These should all return HTTP 403 Forbidden
curl -I https://your-domain/.env
curl -I https://your-domain/.git/config
curl -I https://your-domain/admin
curl -I https://your-domain/backup.sql
curl -I https://your-domain/actuator/env
```

## What Gets Blocked

### 1. Environment Files & Credentials
- `.env`, `.env.local`, `.env.production`, `.envrc`
- `credentials.json`, `config.json`
- `.aws/`, `.ssh/` directories

### 2. Git Repository Access
- `.git/` directories
- `.gitignore` files

### 3. Admin Panels
- `/admin` paths
- `adminer.php`
- `phpmyadmin` / `phpMyAdmin`

### 4. Debug Endpoints
- Spring Boot Actuator: `/actuator/*`
- Heap dumps: `/heapdump`
- Jolokia: `/jolokia`
- ASP.NET: `/trace.axd`

### 5. Database Dumps & Backups
- `.sql` files
- `dump*`, `backup*`, `database*` paths

## Security Considerations

- **Never commit your API token** - use environment variables
- **Token scope:** Create a token with minimal permissions (Zone:Read + Firewall Rules:Edit)
- **Zone access:** Token should only have access to zones you own

## Limitations

- Uses 5 firewall rules per zone (standard Cloudflare limit)
- Expression length is optimized to avoid API limits
- Rules may take 30-60 seconds to propagate globally

## References

- [Cloudflare Firewall Rules Documentation](https://developers.cloudflare.com/firewall/)
- [leaky-paths](https://github.com/ayoubfathi/leaky-paths) - Path list this tool is based on

## License

MIT License