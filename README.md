# Cloudflare WAF Default Config

Most websites expose sensitive files by default. This script deploys basic firewall rules to all your Cloudflare zones to block access to common security risks like environment files, git repositories, admin panels, and debug endpoints.

## Why Use This

Without WAF rules, attackers can easily access:
- Environment files (`.env`) containing API keys and database passwords
- Git repositories (`.git/`) exposing your entire source code history
- Admin panels (phpmyadmin, etc.) allowing database takeover
- Debug endpoints leaking internal system details
- Database dumps and backup files

This provides a simple baseline security layer across all your domains automatically.

## Requirements

Cloudflare API Token with:
- `Zone:Zone:Read` - to list your zones
- `Zone:Firewall Rules:Edit` - to create and edit firewall rules

Create one at: https://dash.cloudflare.com/profile/api-tokens

## Installation

```bash
git clone https://github.com/neuralnexus/cloudflare-waf-default-config.git
cd cloudflare-waf-default-config

export CLOUDFLARE_API_TOKEN="your_token_here"
node deploy-waf.js
```

## Usage

### Dry Run (Preview)

See what changes will be made without applying them:

```bash
export DRY_RUN=true
export CLOUDFLARE_API_TOKEN="your_token"
node deploy-waf.js
```

### Deploy

```bash
export CLOUDFLARE_API_TOKEN="your_token"
node deploy-waf.js
```

The script discovers all active zones in your account and deploys 4 firewall rules to each.

## What Gets Blocked

### Rule 1: Environment Files
Exact matches: `/.env`, `/.env.local`, `/.env.production`, `/.envrc`, etc.

### Rule 2: Sensitive Directories
Directory prefixes: `/.git/`, `/.aws/`, `/.ssh/`, `/.config/`, `/.github/`, etc.

### Rule 3: Sensitive Files
Exact matches: `/id_rsa`, `/credentials.json`, `/config.json`, `/dump.sql`, `/adminer.php`, etc.

### Rule 4: API and Admin Endpoints
Path prefixes: `/admin/`, `/debug/`, `/actuator/`, `/api/admin/`, `/swagger-ui`, etc.

## Testing

After deployment (wait 30-60 seconds):

```bash
# All should return HTTP 403
curl -I https://your-domain/.env
curl -I https://your-domain/.git/config
curl -I https://your-domain/admin
```

## Security Notes

- Never commit your API token
- Use the minimum required permissions
- The token only needs access to zones you own
- Rules may take 30-60 seconds to propagate

## References

- [Cloudflare Firewall Rules](https://developers.cloudflare.com/firewall/)
- [leaky-paths](https://github.com/ayoubfathi/leaky-paths) - Path list reference

## License

MIT
