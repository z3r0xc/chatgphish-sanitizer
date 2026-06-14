/**
 * Service Worker — main background process for ChatGPhish Sanitizer.
 *
 * Responsibilities:
 * 1. Listen for messages from content scripts and popup
 * 2. Run ensemble detection (patternDetector + mlClassifier)
 * 3. Manage scan statistics in chrome.storage.local
 * 4. Update extension icon based on threat level
 * 5. Handle settings persistence in chrome.storage.sync
 *
 * @module serviceWorker
 */

import type {
  DetectionResult,
  ExtensionMessage,
  ExtensionSettings,
  ScanStats,
  ScanTextPayload,
  IconState,
  ThreatLevel,
  DEFAULT_SETTINGS,
} from '../types/index';

import {
  runPatternDetection,
  calculateRegexScore,
  createEnsembleResult,
} from './patternDetector';

import { classifyText, isModelLoaded, preloadModel } from './mlClassifier';

// ─── Default Settings ────────────────────────────────────────────────

const DEFAULTS: ExtensionSettings = {
  enabled: true,
  sensitivity: 0.7,
  useMLModel: true,
  regexWeight: 0.3,
  showNotifications: true,
  autoCleanEnabled: true,
  blockOnThreat: true,
  blockThreshold: 'malicious',
  debugMode: false,
  language: 'en',
};

// ─── State ───────────────────────────────────────────────────────────

let settings: ExtensionSettings = { ...DEFAULTS };
let stats: ScanStats = {
  totalScans: 0,
  threatsBlocked: 0,
  threatsByCategory: {} as Record<string, number>,
  dailyScans: {},
  avgInferenceTime: 0,
  lastScanAt: null,
};

// ─── Initialization ──────────────────────────────────────────────────

/**
 * Load persisted settings and stats on service worker startup.
 */
async function initialize(): Promise<void> {
  console.log('[ServiceWorker] Initializing...');

  // Load settings
  try {
    const stored = await chrome.storage.sync.get('settings');
    if (stored.settings) {
      settings = { ...DEFAULTS, ...stored.settings };
    }
  } catch {
    console.warn('[ServiceWorker] Could not load settings, using defaults');
  }

  // Load stats
  try {
    const stored = await chrome.storage.local.get('stats');
    if (stored.stats) {
      stats = { ...stats, ...stored.stats };
    }
  } catch {
    console.warn('[ServiceWorker] Could not load stats, using fresh state');
  }

  // Pre-load ML model if enabled
  if (settings.useMLModel) {
    preloadModel().then(() => {
      console.log('[ServiceWorker] ML model pre-loaded:', isModelLoaded());
    }).catch(() => {
      console.warn('[ServiceWorker] ML model pre-load failed, will load on first use');
    });
  }

  console.log('[ServiceWorker] Initialized. Enabled:', settings.enabled);
}

// ─── Message Handling ────────────────────────────────────────────────

/**
 * Central message handler for all communication between
 * content scripts, popup, and options pages.
 */
chrome.runtime.onMessage.addListener(
  (message: ExtensionMessage, sender, sendResponse) => {
    handleMessage(message, sender)
      .then(sendResponse)
      .catch((error) => {
        console.error('[ServiceWorker] Message handler error:', error);
        sendResponse(null);
      });

    // Return true to indicate async response
    return true;
  }
);

/**
 * Routes messages to appropriate handlers based on type.
 */
async function handleMessage(
  message: ExtensionMessage,
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.type) {
    case 'SCAN_TEXT':
      return handleScanText(message.payload as ScanTextPayload, sender);

    case 'GET_STATS':
      return stats;

    case 'GET_SETTINGS':
      return settings;

    case 'UPDATE_SETTINGS':
      return handleUpdateSettings(message.payload as Partial<ExtensionSettings>);

    case 'UPDATE_ICON':
      return handleUpdateIcon(sender);

    default:
      console.warn('[ServiceWorker] Unknown message type:', message.type);
      return null;
  }
}

// ─── Scan Handler ────────────────────────────────────────────────────

/**
 * Core scanning logic: runs pattern detection and optionally ML classification,
 * then combines results into an ensemble score.
 */
async function handleScanText(
  payload: ScanTextPayload,
  sender: chrome.runtime.MessageSender
): Promise<DetectionResult> {
  const startTime = performance.now();

  // Run regex pattern detection
  const matches = runPatternDetection(payload.text);
  const regexScore = calculateRegexScore(matches);

  // Run ML classification if enabled
  let mlScore = 0;
  if (settings.useMLModel) {
    try {
      const mlResult = await classifyText(payload.text);
      mlScore = mlResult.confidence;
    } catch (error) {
      console.warn('[ServiceWorker] ML classification failed, using regex only');
    }
  }

  // Create ensemble result
  const result = createEnsembleResult(
    payload.text,
    matches,
    mlScore,
    settings.regexWeight
  );

  // Apply sensitivity threshold
  const adjustedResult = applySensitivity(result);

  // Update statistics
  await updateStats(adjustedResult, startTime);

  // Update icon for the sender's tab
  if (sender.tab?.id) {
    setIconForThreatLevel(sender.tab.id, adjustedResult.threatLevel);
  }

  // Log in debug mode
  if (settings.debugMode) {
    console.log('[ServiceWorker] Scan result:', {
      isMalicious: adjustedResult.isMalicious,
      threatLevel: adjustedResult.threatLevel,
      confidence: adjustedResult.confidence,
      matches: matches.length,
      trigger: payload.trigger,
    });
  }

  return adjustedResult;
}

/**
 * Applies the user's sensitivity setting to adjust detection thresholds.
 * Higher sensitivity = lower threshold for flagging as malicious.
 */
function applySensitivity(result: DetectionResult): DetectionResult {
  const sensitivityFactor = settings.sensitivity;

  // Adjust confidence based on sensitivity
  // sensitivity=1.0 → confidence boosted by 30%
  // sensitivity=0.0 → confidence reduced by 30%
  const adjustment = (sensitivityFactor - 0.5) * 0.6;
  const adjustedConfidence = Math.min(Math.max(result.confidence + adjustment, 0), 1);

  // Recalculate threat level
  let threatLevel: ThreatLevel;
  if (adjustedConfidence < 0.3) threatLevel = 'clean';
  else if (adjustedConfidence < 0.6) threatLevel = 'suspicious';
  else if (adjustedConfidence < 0.85) threatLevel = 'malicious';
  else threatLevel = 'critical';

  const isMalicious = threatLevel === 'malicious' || threatLevel === 'critical';

  return {
    ...result,
    confidence: adjustedConfidence,
    threatLevel,
    isMalicious,
  };
}

// ─── Statistics ──────────────────────────────────────────────────────

/**
 * Updates scan statistics after each scan.
 */
async function updateStats(result: DetectionResult, scanTime: number): Promise<void> {
  stats.totalScans++;
  stats.lastScanAt = Date.now();

  // Update daily scans
  const today = new Date().toISOString().split('T')[0];
  stats.dailyScans[today] = (stats.dailyScans[today] ?? 0) + 1;

  // Clean old daily entries (keep last 30 days)
  const entries = Object.entries(stats.dailyScans);
  if (entries.length > 30) {
    const sorted = entries.sort(([a], [b]) => a.localeCompare(b));
    stats.dailyScans = Object.fromEntries(sorted.slice(-30));
  }

  // Update threat counts
  if (result.isMalicious) {
    stats.threatsBlocked++;
    const cat = result.primaryCategory;
    stats.threatsByCategory[cat] = (stats.threatsByCategory[cat] ?? 0) + 1;
  }

  // Update average inference time
  const totalTime = stats.avgInferenceTime * (stats.totalScans - 1) + scanTime;
  stats.avgInferenceTime = Math.round(totalTime / stats.totalScans);

  // Persist to storage (debounced — don't write every single scan)
  if (stats.totalScans % 5 === 0) {
    try {
      await chrome.storage.local.set({ stats });
    } catch {
      // Non-critical, ignore
    }
  }
}

// ─── Settings ────────────────────────────────────────────────────────

/**
 * Handles settings updates from the options page or popup.
 */
async function handleUpdateSettings(
  newSettings: Partial<ExtensionSettings>
): Promise<ExtensionSettings> {
  settings = { ...settings, ...newSettings };

  try {
    await chrome.storage.sync.set({ settings });
  } catch {
    console.warn('[ServiceWorker] Failed to persist settings');
  }

  console.log('[ServiceWorker] Settings updated:', settings);

  // Notify all tabs about settings change
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'UPDATE_SETTINGS',
        payload: settings,
        timestamp: Date.now(),
      }).catch(() => {
        // Tab might not have content script — ignore
      });
    }
  }

  return settings;
}

// ─── Icon Management ─────────────────────────────────────────────────

/** Icon paths for each state */
const ICON_PATHS: Record<IconState, Record<string, string>> = {
  inactive: {
    '16': 'public/icons/icon16-gray.png',
    '48': 'public/icons/icon48-gray.png',
    '128': 'public/icons/icon128-gray.png',
  },
  clean: {
    '16': 'public/icons/icon16-green.png',
    '48': 'public/icons/icon48-green.png',
    '128': 'public/icons/icon128-green.png',
  },
  suspicious: {
    '16': 'public/icons/icon16-yellow.png',
    '48': 'public/icons/icon48-yellow.png',
    '128': 'public/icons/icon128-yellow.png',
  },
  malicious: {
    '16': 'public/icons/icon16-red.png',
    '48': 'public/icons/icon48-red.png',
    '128': 'public/icons/icon128-red.png',
  },
};

/**
 * Maps a threat level to an icon state.
 */
function threatLevelToIconState(level: ThreatLevel): IconState {
  switch (level) {
    case 'clean': return 'clean';
    case 'suspicious': return 'suspicious';
    case 'malicious': return 'malicious';
    case 'critical': return 'malicious';
  }
}

/**
 * Updates the extension icon for a specific tab.
 */
function setIconForThreatLevel(tabId: number, threatLevel: ThreatLevel): void {
  const iconState = threatLevelToIconState(threatLevel);
  chrome.action.setIcon({
    tabId,
    path: ICON_PATHS[iconState],
  }).catch(() => {
    // Tab might be closed — ignore
  });
}

/**
 * Sets the extension icon directly by icon state (for inactive/clean transitions).
 */
function setIconState(tabId: number, state: IconState): void {
  chrome.action.setIcon({
    tabId,
    path: ICON_PATHS[state],
  }).catch(() => {
    // Tab might be closed — ignore
  });
}

/**
 * Handles UPDATE_ICON message from content script.
 */
async function handleUpdateIcon(sender: chrome.runtime.MessageSender): Promise<void> {
  // Default to inactive
  if (sender.tab?.id) {
    setIconForThreatLevel(sender.tab.id, 'clean');
  }
}

// ─── Tab Lifecycle ───────────────────────────────────────────────────

/**
 * Reset icon to inactive when navigating to a new page.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    setIconState(tabId, 'inactive');
  }
});

/**
 * Set icon to active when entering a supported LLM site.
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const url = tab.url ?? '';
    const isLLMSite = [
      'chatgpt.com', 'chat.openai.com', 'claude.ai',
      'gemini.google.com', 'copilot.microsoft.com', 'poe.com',
    ].some(domain => url.includes(domain));

    if (isLLMSite && settings.enabled) {
      setIconState(activeInfo.tabId, 'clean');
    } else {
      setIconState(activeInfo.tabId, 'inactive');
    }
  } catch {
    // Ignore
  }
});

// ─── Install / Update ────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[ServiceWorker] Extension installed — first run');
    // Open options page on first install
    chrome.runtime.openOptionsPage();
  }
  if (details.reason === 'update') {
    console.log('[ServiceWorker] Extension updated to', chrome.runtime.getManifest().version);
  }
});

// ─── Bootstrap ───────────────────────────────────────────────────────

initialize();
