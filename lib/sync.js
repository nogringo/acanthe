// Sync logic for vault synchronization via Nostr (Bitwarden format)
import {
  DEFAULT_RELAYS,
  KIND_VAULT,
  KIND_DELETION,
  fetchVaultEvents,
  fetchDeletionEvents,
  parseVaultEvent,
  getDeletedEventIds,
  createVaultEvent,
  createDeletionEvent,
  publishEvent,
  subscribeToVault,
  vaultItemToPasskeys
} from './nostr.js';

// Fetch and merge passkeys from Nostr vault
async function fetchAndMergePasskeys(secretKey, publicKey, localPasskeys, relays = DEFAULT_RELAYS, since = 0) {
  // Fetch all vault events
  const vaultEvents = await fetchVaultEvents(publicKey, relays, since);

  // Fetch deletion events
  const deletionEvents = await fetchDeletionEvents(publicKey, relays, since);
  const deletedEventIds = getDeletedEventIds(deletionEvents);

  // Filter out deleted events
  const activeEvents = vaultEvents.filter(e => !deletedEventIds.has(e.id));

  // Parse events and extract passkeys, group by credentialId
  const remotePasskeyMap = new Map();

  for (const event of activeEvents) {
    const parsed = await parseVaultEvent(event, secretKey);
    if (!parsed) continue;

    // Extract passkeys from vault item
    const passkeys = await vaultItemToPasskeys(parsed.vaultItem);

    for (const passkey of passkeys) {
      const { credentialId } = passkey;
      const existing = remotePasskeyMap.get(credentialId);

      // Keep the most recent version (by event created_at or signCount)
      if (!existing || event.created_at > existing.createdAt) {
        remotePasskeyMap.set(credentialId, {
          createdAt: event.created_at,
          eventId: event.id,
          passkey,
          vaultItem: parsed.vaultItem
        });
      }
    }
  }

  // Merge with local passkeys
  const mergedPasskeys = mergePasskeys(localPasskeys, remotePasskeyMap);

  // Find passkeys that need to be published (new local passkeys or updated ones)
  const toPublish = findPasskeysToPublish(localPasskeys, remotePasskeyMap);

  return {
    mergedPasskeys,
    toPublish,
    lastEventTimestamp: getLastEventTimestamp(activeEvents)
  };
}

// Merge local passkeys with remote passkeys
function mergePasskeys(localPasskeys, remotePasskeyMap) {
  const merged = new Map();

  // Add all local passkeys
  for (const passkey of localPasskeys) {
    merged.set(passkey.credentialId, { ...passkey });
  }

  // Merge remote passkeys
  for (const [credentialId, remote] of remotePasskeyMap) {
    const local = merged.get(credentialId);

    if (!local) {
      // New passkey from remote - add it
      merged.set(credentialId, remote.passkey);
    } else {
      // Passkey exists in both - merge (keep highest signCount)
      const mergedPasskey = mergePasskey(local, remote.passkey);
      merged.set(credentialId, mergedPasskey);
    }
  }

  return Array.from(merged.values());
}

// Merge a single passkey (keep highest signCount, latest metadata)
function mergePasskey(local, remote) {
  // Keep the highest signCount
  const signCount = Math.max(local.signCount || 0, remote.signCount || 0);

  // Keep the latest createdAt for metadata (but passkey createdAt should be the original)
  const merged = {
    ...local,
    signCount
  };

  // If remote has newer data (higher signCount), use its metadata
  if (remote.signCount > local.signCount) {
    merged.rpName = remote.rpName || local.rpName;
    merged.userName = remote.userName || local.userName;
    merged.userDisplayName = remote.userDisplayName || local.userDisplayName;
  }

  return merged;
}

// Find passkeys that need to be published to Nostr
function findPasskeysToPublish(localPasskeys, remotePasskeyMap) {
  const toPublish = [];

  for (const passkey of localPasskeys) {
    const remote = remotePasskeyMap.get(passkey.credentialId);

    if (!remote) {
      // New local passkey - needs to be published
      toPublish.push(passkey);
    } else if (passkey.signCount > remote.passkey.signCount) {
      // Local has higher signCount - needs to be published
      toPublish.push(passkey);
    }
  }

  return toPublish;
}

// Get the timestamp of the last event
function getLastEventTimestamp(events) {
  if (events.length === 0) return 0;
  return Math.max(...events.map(e => e.created_at));
}

// Publish a passkey to Nostr vault
async function publishPasskey(passkey, secretKey, relays = DEFAULT_RELAYS) {
  const event = await createVaultEvent(passkey, secretKey);
  return await publishEvent(event, relays);
}

// Publish multiple passkeys to Nostr vault
async function publishPasskeys(passkeys, secretKey, relays = DEFAULT_RELAYS) {
  const results = [];

  for (const passkey of passkeys) {
    const result = await publishPasskey(passkey, secretKey, relays);
    results.push({
      credentialId: passkey.credentialId,
      ...result
    });
  }

  return results;
}

// Delete a passkey from Nostr (publish deletion event)
async function deletePasskeyFromNostr(eventId, secretKey, relays = DEFAULT_RELAYS) {
  const deletionEvent = createDeletionEvent(eventId, secretKey);
  return await publishEvent(deletionEvent, relays);
}

// Start real-time sync subscription
function startSyncSubscription(secretKey, publicKey, relays, onPasskeyReceived, onDeletionReceived) {
  return subscribeToVault(
    publicKey,
    relays,
    async (event) => {
      if (event.kind === KIND_VAULT) {
        const parsed = await parseVaultEvent(event, secretKey);
        if (parsed) {
          // Extract passkeys from vault item
          const passkeys = await vaultItemToPasskeys(parsed.vaultItem);
          for (const passkey of passkeys) {
            onPasskeyReceived({
              eventId: event.id,
              createdAt: event.created_at,
              passkey
            });
          }
        }
      } else if (event.kind === KIND_DELETION) {
        const deletedIds = getDeletedEventIds([event]);
        for (const eventId of deletedIds) {
          onDeletionReceived(eventId);
        }
      }
    },
    () => {
      // Initial sync complete (EOSE)
    }
  );
}

// Export sync utilities
export {
  fetchAndMergePasskeys,
  mergePasskeys,
  mergePasskey,
  findPasskeysToPublish,
  publishPasskey,
  publishPasskeys,
  deletePasskeyFromNostr,
  startSyncSubscription
};
