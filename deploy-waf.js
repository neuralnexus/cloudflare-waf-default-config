#!/usr/bin/env node
/**
 * Cloudflare WAF Rule Deployment Script
 * Blocks sensitive paths and endpoints across all domains
 * Compatible with Cloudflare Free Plan (up to 5 firewall rules per zone)
 */

// Configuration
const CONFIG = {
  DRY_RUN: process.env.DRY_RUN === 'true',
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000,
  REQUESTS_PER_SECOND: 4,
  API_BASE: 'https://api.cloudflare.com/client/v4',
};

// Rate limiting queue
class RateLimiter {
  constructor(requestsPerSecond) {
    this.interval = 1000 / requestsPerSecond;
    this.lastRequest = 0;
  }

  async wait() {
    const now = Date.now();
    const elapsed = now - this.lastRequest;
    if (elapsed < this.interval) {
      await sleep(this.interval - elapsed);
    }
    this.lastRequest = Date.now();
  }
}

const rateLimiter = new RateLimiter(CONFIG.REQUESTS_PER_SECOND);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchWithRetry(url, options, attempt = 1) {
  await rateLimiter.wait();
  
  try {
    const response = await fetch(url, options);
    
    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after') || 5;
      console.log(`  ⏳ Rate limited. Waiting ${retryAfter}s before retry...`);
      await sleep(retryAfter * 1000);
      if (attempt < CONFIG.MAX_RETRIES) {
        return fetchWithRetry(url, options, attempt + 1);
      }
    }
    
    return response;
  } catch (error) {
    if (attempt < CONFIG.MAX_RETRIES) {
      console.log(`  🔄 Retrying... (${attempt}/${CONFIG.MAX_RETRIES})`);
      await sleep(CONFIG.RETRY_DELAY * attempt);
      return fetchWithRetry(url, options, attempt + 1);
    }
    throw error;
  }
}

async function getAllZones() {
  const accountFilter = process.env.CLOUDFLARE_ACCOUNT_FILTER;
  
  try {
    const zones = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await fetchWithRetry(
        `${CONFIG.API_BASE}/zones?page=${page}&per_page=50`,
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
          paused: z.paused,
          account_name: z.account?.name,
          account_id: z.account?.id
        })));
        
        hasMore = data.result_info.total_pages > page;
        page++;
      } else {
        hasMore = false;
      }
    }
    
    // Filter to only active zones, and account if specified
    const filteredZones = zones.filter(z => {
      const isActive = z.status === "active" && !z.paused;
      
      if (accountFilter && isActive) {
        const filterLower = accountFilter.toLowerCase();
        const accountLower = (z.account_name || '').toLowerCase();
        const isMatchingAccount = accountLower.includes(filterLower);
        
        if (!isMatchingAccount) {
          console.log(`  ⚠️  Skipping ${z.name} (account: ${z.account_name})`);
        }
        return isMatchingAccount;
      }
      
      return isActive;
    });
    
    if (accountFilter) {
      console.log(`  Filtered to ${filteredZones.length} zones from account matching "${accountFilter}"`);
    }
    
    return filteredZones;
  } catch (error) {
    console.error("❌ Error fetching zones:", error.message);
    return [];
  }
}

// Priority paths to block (most critical - reduces list to fit free tier limits)
// Using starts_with for directories and eq for exact matches to avoid false positives
const CRITICAL_PATHS = {
  // Environment files - exact match
  envFiles: [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.dev',
    '/.envrc',
  ],
  // Directories - starts_with
  directories: [
    '/.git/',
    '/.aws/',
    '/.ssh/',
    '/.config/',
    '/.github/',
    '/.idea/',
    '/.vscode/',
  ],
  // Specific files - exact match
  files: [
    '/id_rsa',
    '/id_dsa',
    '/.htpasswd',
    '/config.json',
    '/config.php',
    '/appsettings.json',
    '/credentials.json',
    '/dump.sql',
    '/database.sql',
    '/backup.sql',
    '/adminer.php',
    '/phpmyadmin',
    '/phpMyAdmin',
    '/trace.axd',
    '/bundle.js.map',
    '/app.js.map',
    '/docker-compose.yml',
    '/docker-compose.yaml',
    '/Dockerfile',
    '/package.json',
    '/composer.json',
    '/composer.lock',
    '/error.log',
    '/access.log',
    '/debug.log',
    '/web.config',
    '/.htaccess',
  ],
  // Path prefixes - starts_with (more specific than contains)
  prefixes: [
    '/admin/',
    '/debug/',
    '/actuator/',
    '/api/admin/',
    '/api/debug/',
    '/api/config/',
    '/api/keys/',
    '/api/secrets/',
    '/api/internal/',
    '/graphql/v1/',
    '/swagger-ui',
    '/api-docs',
    '/actuator/env',
    '/actuator/configprops',
    '/actuator/heapdump',
    '/heapdump',
    '/jolokia',
  ],
};

async function listFirewallRules(zoneId) {
  try {
    const allRules = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await fetchWithRetry(
        `${CONFIG.API_BASE}/zones/${zoneId}/firewall/rules?page=${page}&per_page=50`,
        {
          headers: {
            "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
            "Content-Type": "application/json"
          }
        }
      );
      
      const data = await response.json();
      if (data.success && data.result) {
        allRules.push(...data.result);
        hasMore = data.result_info.total_pages > page;
        page++;
      } else {
        hasMore = false;
      }
    }
    
    return allRules;
  } catch (error) {
    console.error(`❌ Error listing firewall rules:`, error.message);
    return [];
  }
}

async function deleteFirewallRule(zoneId, ruleId) {
  if (CONFIG.DRY_RUN) {
    console.log(`    [DRY RUN] Would delete rule: ${ruleId}`);
    return true;
  }
  
  try {
    const response = await fetchWithRetry(
      `${CONFIG.API_BASE}/zones/${zoneId}/firewall/rules/${ruleId}`,
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

async function createFirewallRule(zoneId, description, expression, priority = 10) {
  if (CONFIG.DRY_RUN) {
    console.log(`    [DRY RUN] Would create rule: ${description}`);
    return { id: 'dry-run', description, expression };
  }
  
  try {
    const response = await fetchWithRetry(
      `${CONFIG.API_BASE}/zones/${zoneId}/firewall/rules`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action: "block",
          priority: priority,
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

function buildPathExpression(paths, type = 'eq') {
  if (type === 'eq') {
    return paths.map(path => `http.request.uri.path eq "${path}"`).join(' or ');
  } else if (type === 'starts_with') {
    return paths.map(path => `starts_with(http.request.uri.path, "${path}")`).join(' or ');
  } else if (type === 'ends_with') {
    return paths.map(path => `ends_with(http.request.uri.path, "${path}")`).join(' or ');
  }
  return '';
}

async function deployRulesToDomain(domain, zoneId) {
  console.log(`\n🔒 Deploying WAF rules to ${domain}...`);
  
  try {
    // Get existing rules with pagination
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
    let priority = 10;
    
    // Rule 1: Block environment files (exact matches)
    const envExpression = buildPathExpression(CRITICAL_PATHS.envFiles, 'eq');
    if (envExpression) {
      const rule = await createFirewallRule(
        zoneId,
        "[WAF] Block environment files",
        envExpression,
        priority++
      );
      if (rule) created.push(rule);
    }
    
    // Rule 2: Block sensitive directories (starts_with)
    const dirExpression = buildPathExpression(CRITICAL_PATHS.directories, 'starts_with');
    if (dirExpression) {
      const rule = await createFirewallRule(
        zoneId,
        "[WAF] Block sensitive directories",
        dirExpression,
        priority++
      );
      if (rule) created.push(rule);
    }
    
    // Rule 3: Block sensitive files (exact matches)
    const fileExpression = buildPathExpression(CRITICAL_PATHS.files, 'eq');
    if (fileExpression) {
      const rule = await createFirewallRule(
        zoneId,
        "[WAF] Block sensitive files",
        fileExpression,
        priority++
      );
      if (rule) created.push(rule);
    }
    
    // Rule 4: Block API/admin prefixes (starts_with)
    const prefixExpression = buildPathExpression(CRITICAL_PATHS.prefixes, 'starts_with');
    if (prefixExpression) {
      const rule = await createFirewallRule(
        zoneId,
        "[WAF] Block API and admin endpoints",
        prefixExpression,
        priority++
      );
      if (rule) created.push(rule);
    }
    
    console.log(`  ✨ Created ${created.length} WAF rules`);
    return { domain, rules: created.length, error: null };
  } catch (error) {
    console.error(`  ❌ Error deploying to ${domain}:`, error.message);
    return { domain, rules: 0, error: error.message };
  }
}

async function main() {
  console.log("🛡️  Cloudflare WAF Rule Deployment\n");
  
  if (CONFIG.DRY_RUN) {
    console.log("🏃 DRY RUN MODE - No changes will be made\n");
  }
  
  if (!process.env.CLOUDFLARE_API_TOKEN) {
    console.error("❌ CLOUDFLARE_API_TOKEN environment variable is required");
    console.log("\nTo get your API token:");
    console.log("1. Go to https://dash.cloudflare.com/profile/api-tokens");
    console.log("2. Create a token with these permissions:");
    console.log("   - Zone:Read, Firewall Rules:Edit");
    console.log("   - Include all zones or specific zones");
    console.log("\nSet DRY_RUN=true to preview changes without applying them.");
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
  
  console.log("\n⚠️  This script will create up to 4 firewall rules per zone");
  console.log("Rules will block access to sensitive paths and endpoints.\n");
  
  const results = [];
  
  for (const zone of zones) {
    const result = await deployRulesToDomain(zone.name, zone.zone_id);
    results.push(result);
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
  
  const successCount = results.filter(r => !r.error).length;
  const failCount = results.filter(r => r.error).length;
  
  console.log(`\n✨ Done! ${successCount} zones processed successfully, ${failCount} failed.`);
  
  if (CONFIG.DRY_RUN) {
    console.log("\n🏃 This was a dry run. Set DRY_RUN=false to apply changes.");
  } else {
    console.log("\nNote: Changes may take 30-60 seconds to propagate globally.");
    console.log("\nTo verify rules are working:");
    console.log("  curl -I https://your-domain/.env");
    console.log("  curl -I https://your-domain/.git/config");
    console.log("  curl -I https://your-domain/admin");
    console.log("\nAll should return HTTP 403 Forbidden.");
  }
}

main().catch(error => {
  console.error("❌ Fatal error:", error);
  process.exit(1);
});
