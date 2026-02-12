// Blossom client for favicon storage
// Uses nostr-tools BlossomClient (NIP-B7)

import { BlossomClient } from 'nostr-tools/nipb7';
import { finalizeEvent } from 'nostr-tools';

// Default Blossom servers
const DEFAULT_BLOSSOM_SERVERS = [
  'https://blossom.primal.net',
  'https://blossom.yakihonne.com',
  'https://blossom-01.uid.ovh',
  'https://blossom-02.uid.ovh'
];

/**
 * Fetch favicon from a website
 * @param {string} domain - Website domain (e.g., "example.com")
 * @returns {Promise<Blob | null>}
 */
async function fetchFavicon(domain) {
  const urls = [
    // Direct from site
    `https://${domain}/favicon.ico`,
    `https://${domain}/favicon.png`,
    // Fallback services
    `https://favicon.yandex.net/favicon/${domain}`,
    `https://icons.duckduckgo.com/ip3/${domain}.ico`,
    `https://icon.horse/icon/${domain}`,
    `https://api.faviconkit.com/${domain}/64`,
    `https://www.google.com/s2/favicons?domain=${domain}&sz=64`
  ];

  for (const url of urls) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        const blob = await response.blob();
        if (blob.size < 100) continue;
        return blob;
      }
    } catch {
      // Try next URL
    }
  }

  return null;
}

/**
 * Upload favicon to Blossom servers (uploads to ALL servers for redundancy)
 * @param {Blob} blob - Favicon blob
 * @param {Uint8Array} secretKey - Nostr secret key
 * @param {string[]} servers - Blossom servers
 * @returns {Promise<{hash: string, url: string, successCount: number} | null>}
 */
async function uploadFavicon(blob, secretKey, servers = DEFAULT_BLOSSOM_SERVERS) {
  // Upload to all servers in parallel
  const uploadPromises = servers.map(async (server) => {
    try {
      const signer = {
        signEvent: async (event) => finalizeEvent(event, secretKey)
      };
      const client = new BlossomClient(server, signer);

      const result = await client.uploadBlob(blob);
      if (result && result.sha256) {
        return { server, hash: result.sha256, url: result.url || `${server}/${result.sha256}` };
      }
      return null;
    } catch {
      return null;
    }
  });

  const results = await Promise.allSettled(uploadPromises);
  const successes = results
    .filter(r => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value);

  if (successes.length === 0) {
    return null;
  }

  return {
    hash: successes[0].hash,
    url: successes[0].url,
    successCount: successes.length
  };
}

/**
 * Get or upload favicon for a domain
 * @param {string} domain - Website domain
 * @param {Uint8Array} secretKey - Nostr secret key
 * @param {string[]} servers - Blossom servers
 * @returns {Promise<{hash: string, url: string} | null>}
 */
async function getOrUploadFavicon(domain, secretKey, servers = DEFAULT_BLOSSOM_SERVERS) {
  const favicon = await fetchFavicon(domain);
  if (!favicon) return null;

  return await uploadFavicon(favicon, secretKey, servers);
}

/**
 * Get favicon URL from hash
 * @param {string} hash - SHA256 hash
 * @param {string[]} servers - Blossom servers
 * @returns {string} URL to favicon
 */
function getFaviconUrl(hash, servers = DEFAULT_BLOSSOM_SERVERS) {
  return `${servers[0]}/${hash}`;
}

/**
 * Check if favicon exists on any server
 * @param {string} hash - SHA256 hash
 * @param {string[]} servers - Blossom servers
 * @returns {Promise<string | null>} URL if exists, null otherwise
 */
async function checkFaviconExists(hash, servers = DEFAULT_BLOSSOM_SERVERS) {
  for (const server of servers) {
    try {
      const response = await fetch(`${server}/${hash}`, { method: 'HEAD' });
      if (response.ok) {
        return `${server}/${hash}`;
      }
    } catch {
      // Try next server
    }
  }
  return null;
}

export {
  DEFAULT_BLOSSOM_SERVERS,
  fetchFavicon,
  uploadFavicon,
  getOrUploadFavicon,
  getFaviconUrl,
  checkFaviconExists
};
