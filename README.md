# Neural Nexus WAF Default Config

Automated WAF (Web Application Firewall) deployment for Cloudflare Free Plan users. Automatically discovers all domains in your Cloudflare account and deploys 5 security rules to block access to sensitive paths.

## Features

- ✅ **Auto-discovers all zones** in your Cloudflare account
- ✅ **5 security rules** (Free Plan limit) covering:
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

# Install dependencies (none required - uses Node.js built-in fetch)

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

Found 20 active zones:
  • cyiro.com
  • aiadjacent.com
  • milemadness.com
  • ...

⚠️  This script will create up to 5 firewall rules per zone (Free Plan limit)
Rules will block access to sensitive paths and endpoints.

🔒 Deploying WAF rules to cyiro.com...
  Found 0 existing firewall rules
  ✅ Created: [WAF] Block environment files and credentials
  ✅ Created: [WAF] Block Git repository access
  ✅ Created: [WAF] Block admin panel access
  ✅ Created: [WAF] Block debug endpoints
  ✅ Created: [WAF] Block database dumps and backups
  ✨ Created 5 WAF rules

🔒 Deploying WAF rules to aiadjacent.com...
...

📊 Deployment Summary:
====================
cyiro.com: ✅ 5 rules deployed
aiadjacent.com: ✅ 5 rules deployed
milemadness.com: ✅ 5 rules deployed
...

✨ Done! WAF protection is now active on your domains.
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
- Git configuration files

### 3. Admin Panels
- `/admin` paths
- `adminer.php`
- `phpmyadmin` / `phpMyAdmin`

### 4. Debug Endpoints
- Spring Boot Actuator: `/actuator/*`
- Heap dumps: `/heapdump`
- Jolokia: `/jolokia`
- ASP.NET: `/trace.axd`
- Generic: `/debug/*`

### 5. Database Dumps & Backups
- `.sql` files
- `dump*`, `backup*`, `database*` paths

## Limitations

- **Free Plan:** Limited to 5 firewall rules per zone (script uses all 5)
- **Expression length:** Very long lists of paths are grouped to avoid API limits
- **Propagation time:** Rules may take 30-60 seconds to go live globally

## Manual Alternative

If you prefer not to use the script, you can manually create the same rules in the Cloudflare Dashboard:

1. Go to https://dash.cloudflare.com
2. Select your domain
3. **Security → WAF → Custom rules**
4. Create the 5 rules listed in the "What Gets Blocked" section above

## Security Considerations

- **Never commit your API token** - use environment variables
- **Token scope:** Create a token with minimal permissions (Zone:Read + Firewall Rules:Edit)
- **Zone access:** Token should only have access to zones you own
- **Rule priority:** Rules are created with priority 10 (evaluated early)

## Cloudflare Free Plan

This script is designed specifically for Cloudflare Free Plan users:
- 5 firewall rules per zone (maximum)
- No account-level rulesets
- No managed rulesets
- Basic WAF expressions

For Enterprise/Business plans, consider using:
- Account-level rulesets
- Managed rulesets
- Custom rate limiting

## License

MIT License - Free to use and modify.

## Contributing

Pull requests welcome! This is a community security tool to help protect Cloudflare Free Plan users.

## References

- [Cloudflare Firewall Rules Documentation](https://developers.cloudflare.com/firewall/)
- [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
- [leaky-paths](https://github.com/ayoubfathi/leaky-paths) - The original path list this tool is based on