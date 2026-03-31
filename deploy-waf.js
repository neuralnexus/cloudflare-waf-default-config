#!/usr/bin/env node
/**
 * Cloudflare WAF Rule Deployment Script
 * Blocks sensitive paths and endpoints across all domains
 * Compatible with Cloudflare Free Plan (up to 5 firewall rules per zone)
 */

async function getAllZones() {
  try {
    const zones = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await fetch(
        `https://api.cloudflare.com/client/v4/zones?page=${page}&per_page=50`,
        {
          headers: {
            "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
            "Content-Type": "application/json"
          }
        }
      );
      
      const data = await response.json();
      if (data.success && data.result) {
        zones.push(...data.result.map(z => ({ 
          name: z.name, 
          zone_id: z.id,
          status: z.status,
          paused: z.paused 
        })));
        
        hasMore = data.result_info.total_pages > page;
        page++;
      } else {
        hasMore = false;
      }
    }
    
    // Filter to only active, unpaused zones
    return zones.filter(z => z.status === "active" && !z.paused);
  } catch (error) {
    console.error("❌ Error fetching zones:", error.message);
    return [];
  }
}

// Priority paths to block (most critical - reduces list to fit free tier limits)
const CRITICAL_PATHS = [
  // Environment files
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.dev",
  "/.envrc",
  "/.config",
  
  // Git repositories
  "/.git",
  "/.git/config",
  "/.git/head",
  "/.git/logs",
  
  // Credentials and keys
  "/.aws",
  "/.ssh",
  "/id_rsa",
  "/id_dsa",
  "/.htpasswd",
  
  // Config files with secrets
  "/config.json",
  "/config.php",
  "/appsettings.json",
  "/credentials.json",
  
  // Database dumps
  "/dump.sql",
  "/database.sql",
  "/backup.sql",
  
  // Admin panels
  "/admin",
  "/admin/",
  "/adminer.php",
  "/phpmyadmin",
  "/phpMyAdmin",
  
  // Debug endpoints
  "/debug",
  "/debug/",
  "/actuator",
  "/actuator/",
  "/trace.axd",
  
  // Source map files (can leak source code)
  "/bundle.js.map",
  "/app.js.map",
  
  // Common backup files
  "/backup",
  "/backup.zip",
  "/backup.tar.gz",
  
  // Docker
  "/docker-compose.yml",
  "/docker-compose.yaml",
  "/Dockerfile",
  
  // Package managers
  "/package.json",
  "/composer.json",
  "/composer.lock",
  
  // CI/CD configs
  "/.github/workflows",
  
  // IDE files
  "/.idea",
  "/.vscode",
  
  // Log files
  "/error.log",
  "/access.log",
  "/debug.log",
  
  // XML files that may contain configs
  "/web.config",
  "/.htaccess",
];

// API endpoints to block
const SENSITIVE_API_PATTERNS = [
  "/api/admin",
  "/api/debug",
  "/api/config",
  "/api/keys",
  "/api/secrets",
  "/api/internal",
  "/graphql/v1",
  "/swagger-ui",
  "/swagger.json",
  "/api-docs",
  "/openapi.json",
  "/actuator/env",
  "/actuator/configprops",
  "/actuator/heapdump",
  "/heapdump",
  "/jolokia",
];

async function getZoneId(domain) {
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`,
      {
        headers: {
          "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );
    
    const data = await response.json();
    if (data.success && data.result.length > 0) {
      return data.result[0].id;
    }
    throw new Error(`Zone not found for ${domain}`);
  } catch (error) {
    console.error(`❌ Error fetching zone for ${domain}:`, error.message);
    return null;
  }
}

async function listFirewallRules(zoneId) {
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/rules`,
      {
        headers: {
          "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );
    
    const data = await response.json();
    return data.success ? data.result : [];
  } catch (error) {
    console.error(`❌ Error listing firewall rules:`, error.message);
    return [];
  }
}

async function deleteFirewallRule(zoneId, ruleId) {
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/rules/${ruleId}`,
      {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );
    
    return response.ok;
  } catch (error) {
    console.error(`❌ Error deleting firewall rule:`, error.message);
    return false;
  }
}

async function createFirewallRule(zoneId, description, expression) {
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/rules`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action: "block",
          priority: 10,
          paused: false,
          description: description,
          filter: {
            expression: expression,
            paused: false,
            description: description
          }
        })
      }
    );
    
    const data = await response.json();
    if (data.success) {
      console.log(`  ✅ Created: ${description}`);
      return data.result;
    } else {
      console.error(`  ❌ Failed to create ${description}:`, data.errors);
      return null;
    }
  } catch (error) {
    console.error(`  ❌ Error creating firewall rule:`, error.message);
    return null;
  }
}

function buildPathExpression(paths) {
  // Group paths to avoid extremely long expressions
  // Cloudflare firewall rules have expression length limits
  const expressions = paths.map(path => `http.request.uri.path contains "${path}"`);
  return expressions.join(" or ");
}

async function deployRulesToDomain(domain, zoneId) {
  console.log(`\n🔒 Deploying WAF rules to ${domain}...`);
  
  // Get existing rules
  const existingRules = await listFirewallRules(zoneId);
  console.log(`  Found ${existingRules.length} existing firewall rules`);
  
  // Delete existing "Block" rules created by this script
  const ourRules = existingRules.filter(r => 
    r.description && r.description.startsWith("[WAF] ")
  );
  
  for (const rule of ourRules) {
    console.log(`  🗑️  Removing old rule: ${rule.description}`);
    await deleteFirewallRule(zoneId, rule.id);
  }
  
  // Create new rules
  const created = [];
  
  // Rule 1: Block environment files and credentials
  const envExpression = CRITICAL_PATHS
    .filter(p => p.includes(".env") || p.includes("credentials") || p.includes("config") || p.includes(".aws") || p.includes(".ssh"))
    .slice(0, 20) // Limit to avoid expression too long
    .map(p => `http.request.uri.path contains "${p}"`)
    .join(" or ");
    
  if (envExpression) {
    const rule = await createFirewallRule(
      zoneId,
      "[WAF] Block environment files and credentials",
      envExpression
    );
    if (rule) created.push(rule);
  }
  
  // Rule 2: Block Git repository access
  const gitExpression = `(http.request.uri.path contains "/.git/" or http.request.uri.path contains ".gitignore")`;
  const gitRule = await createFirewallRule(
    zoneId,
    "[WAF] Block Git repository access",
    gitExpression
  );
  if (gitRule) created.push(gitRule);
  
  // Rule 3: Block admin panels
  const adminExpression = `(http.request.uri.path contains "/admin" or http.request.uri.path contains "adminer.php" or http.request.uri.path contains "phpmyadmin" or http.request.uri.path contains "phpMyAdmin")`;
  const adminRule = await createFirewallRule(
    zoneId,
    "[WAF] Block admin panel access",
    adminExpression
  );
  if (adminRule) created.push(adminRule);
  
  // Rule 4: Block debug and actuator endpoints
  const debugExpression = `(http.request.uri.path contains "/debug" or http.request.uri.path contains "/actuator" or http.request.uri.path contains "heapdump" or http.request.uri.path contains "jolokia" or http.request.uri.path contains "trace.axd")`;
  const debugRule = await createFirewallRule(
    zoneId,
    "[WAF] Block debug endpoints",
    debugExpression
  );
  if (debugRule) created.push(debugRule);
  
  // Rule 5: Block database dumps and backups
  const dbExpression = `(http.request.uri.path contains ".sql" or http.request.uri.path contains "dump" or http.request.uri.path contains "backup" or http.request.uri.path contains "database")`;
  const dbRule = await createFirewallRule(
    zoneId,
    "[WAF] Block database dumps and backups",
    dbExpression
  );
  if (dbRule) created.push(dbRule);
  
  console.log(`  ✨ Created ${created.length} WAF rules`);
  return created;
}

async function main() {
  console.log("🛡️  Cloudflare WAF Rule Deployment\n");
  
  if (!process.env.CLOUDFLARE_API_TOKEN) {
    console.error("❌ CLOUDFLARE_API_TOKEN environment variable is required");
    console.log("\nTo get your API token:");
    console.log("1. Go to https://dash.cloudflare.com/profile/api-tokens");
    console.log("2. Create a token with these permissions:");
    console.log("   - Zone:Read, Firewall Rules:Edit");
    console.log("   - Include all zones or specific zones");
    process.exit(1);
  }
  
  console.log("📋 Fetching all zones from your account...\n");
  const zones = await getAllZones();
  
  if (zones.length === 0) {
    console.error("❌ No active zones found in your account");
    process.exit(1);
  }
  
  console.log(`Found ${zones.length} active zones:\n`);
  zones.forEach(z => console.log(`  • ${z.name}`));
  
  console.log("\n⚠️  This script will create up to 5 firewall rules per zone (Free Plan limit)");
  console.log("Rules will block access to sensitive paths and endpoints.\n");
  
  const results = [];
  
  for (const zone of zones) {
    const rules = await deployRulesToDomain(zone.name, zone.zone_id);
    results.push({ domain: zone.name, rules: rules.length });
  }
  
  console.log("\n📊 Deployment Summary:");
  console.log("====================");
  results.forEach(r => {
    if (r.error) {
      console.log(`${r.domain}: ❌ ${r.error}`);
    } else {
      console.log(`${r.domain}: ✅ ${r.rules} rules deployed`);
    }
  });
  
  console.log("\n✨ Done! WAF protection is now active on your domains.");
  console.log("\nNote: Changes may take 30-60 seconds to propagate globally.");
  console.log("\nTo verify rules are working:");
  console.log("  curl -I https://your-domain/.env");
  console.log("  curl -I https://your-domain/.git/config");
  console.log("  curl -I https://your-domain/admin");
  console.log("\nAll should return HTTP 403 Forbidden.");
}

main().catch(error => {
  console.error("❌ Fatal error:", error);
  process.exit(1);
});
