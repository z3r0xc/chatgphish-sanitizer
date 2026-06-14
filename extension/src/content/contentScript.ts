/**
 * Content Script — intercepts paste and submit events on LLM chat interfaces.
 *
 * Injected into ChatGPT, Claude, Gemini, Copilot, and Poe pages.
 * Scans text BEFORE it enters the input field, communicating with
 * the background service worker for detection.
 *
 * Architecture:
 * 1. Listen for 'paste' events globally
 * 2. Extract clipboard text
 * 3. Send to service worker via chrome.runtime.sendMessage
 * 4. If malicious: prevent default, show toast notification
 * 5. If clean: allow normal paste flow
 *
 * Also observes DOM for input changes (debounced) to catch
 * manually typed or modified text before submission.
 *
 * @module contentScript
 */

import type {
  DetectionResult,
  ExtensionMessage,
  ExtensionSettings,
  ToastConfig,
  DEFAULT_SETTINGS,
} from '../types/index';

// ─── Configuration ───────────────────────────────────────────────────

/** CSS selectors for input fields on supported LLM platforms */
const SITE_SELECTORS: Record<string, string> = {
  'chatgpt.com': '#prompt-textarea',
  'chat.openai.com': '#prompt-textarea',
  'claude.ai': '[contenteditable="true"]',
  'gemini.google.com': '.ql-editor, [contenteditable="true"]',
  'copilot.microsoft.com': '#searchbox, textarea',
  'poe.com': 'textarea[class*="TextArea"]',
};

/** Debounce interval for DOM observation (ms) */
const DEBOUNCE_MS = 300;

/** Toast auto-dismiss duration (ms) */
const TOAST_DURATION = 5000;

// ─── State ───────────────────────────────────────────────────────────

let currentSettings: ExtensionSettings | null = null;
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
let lastScannedText = '';

// ─── Initialization ──────────────────────────────────────────────────

/**
 * Main entry point. Loads settings and sets up event listeners.
 */
async function init(): Promise<void> {
  console.log('[ChatGPhish] Content script loaded on', window.location.hostname);

  // Load current settings from service worker
  currentSettings = await requestSettings();

  if (!currentSettings?.enabled) {
    console.log('[ChatGPhish] Extension disabled, skipping initialization');
    return;
  }

  // Set up paste interception
  document.addEventListener('paste', handlePaste, true);

  // Set up submit interception
  document.addEventListener('keydown', handleKeyDown, true);

  // Set up DOM observer for input changes
  setupInputObserver();

  // Listen for settings changes from popup/options
  chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
    if (message.type === 'UPDATE_SETTINGS') {
      currentSettings = message.payload as ExtensionSettings;
      console.log('[ChatGPhish] Settings updated');
    }
    if (message.type === 'SHOW_TOAST') {
      const config = message.payload as ToastConfig;
      showToast(config);
    }
  });

  console.log('[ChatGPhish] Content script initialized successfully');
}

// ─── Paste Interception ──────────────────────────────────────────────

/**
 * Handles paste events. Extracts clipboard text and sends it
 * for scanning BEFORE allowing it into the input field.
 *
 * If the scan detects a threat and settings.blockOnThreat is true,
 * the paste is prevented and a toast notification is shown.
 */
async function handlePaste(event: ClipboardEvent): Promise<void> {
  if (!currentSettings?.enabled) return;

  const pastedText = event.clipboardData?.getData('text/plain') ?? '';
  if (!pastedText.trim()) return;

  console.log('[ChatGPhish] Paste intercepted, scanning', pastedText.length, 'chars');

  const result = await scanText(pastedText, 'paste');
  if (!result) return;

  if (result.isMalicious && currentSettings.blockOnThreat) {
    // Prevent the paste from reaching the input
    event.preventDefault();
    event.stopPropagation();

    console.warn('[ChatGPhish] ⚠️ Malicious paste BLOCKED:', result.primaryCategory);

    showToast({
      threatLevel: result.threatLevel,
      category: result.primaryCategory,
      matchCount: result.matches.length,
      wasCleaned: false,
      duration: TOAST_DURATION,
    });

    // If auto-clean is enabled, insert cleaned text instead
    if (currentSettings.autoCleanEnabled && result.cleanedText !== pastedText) {
      insertTextAtCursor(result.cleanedText);
      console.log('[ChatGPhish] Cleaned text inserted instead');
    }
  } else if (result.threatLevel === 'suspicious') {
    // Allow paste but show warning
    console.warn('[ChatGPhish] ⚡ Suspicious paste detected:', result.primaryCategory);

    showToast({
      threatLevel: result.threatLevel,
      category: result.primaryCategory,
      matchCount: result.matches.length,
      wasCleaned: false,
      duration: TOAST_DURATION,
    });
  }

  // Update the service worker about this tab's state
  updateTabIcon(result);
}

// ─── Submit Interception ─────────────────────────────────────────────

/**
 * Intercepts Enter key presses to scan the full input text
 * before it's submitted to the LLM.
 *
 * This catches cases where text was typed manually or modified
 * after a clean paste.
 */
async function handleKeyDown(event: KeyboardEvent): Promise<void> {
  if (!currentSettings?.enabled) return;
  if (event.key !== 'Enter' || event.shiftKey) return;

  const inputText = getCurrentInputText();
  if (!inputText || inputText === lastScannedText) return;

  // Don't block if this is the same text we already scanned
  const result = await scanText(inputText, 'submit');
  if (!result) return;

  if (result.isMalicious && currentSettings.blockOnThreat) {
    event.preventDefault();
    event.stopPropagation();

    console.warn('[ChatGPhish] ⚠️ Malicious submit BLOCKED:', result.primaryCategory);

    showToast({
      threatLevel: result.threatLevel,
      category: result.primaryCategory,
      matchCount: result.matches.length,
      wasCleaned: false,
      duration: TOAST_DURATION,
    });
  }

  updateTabIcon(result);
}

// ─── DOM Observation ─────────────────────────────────────────────────

/**
 * Sets up a MutationObserver on the input field to detect
 * text changes that aren't captured by paste/keydown events.
 *
 * Uses debouncing to avoid excessive scanning during fast typing.
 */
function setupInputObserver(): void {
  const selector = getSelectorForCurrentSite();
  if (!selector) return;

  // Wait for the input element to appear
  const observer = new MutationObserver(() => {
    const input = document.querySelector(selector);
    if (input) {
      observer.disconnect();
      observeInput(input as HTMLElement);
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

/**
 * Observes a specific input element for text content changes.
 */
function observeInput(element: HTMLElement): void {
  const inputObserver = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);

    debounceTimer = setTimeout(() => {
      const text = element.textContent ?? '';
      if (text && text !== lastScannedText && text.length > 20) {
        // Only scan if text is substantial enough (avoids scanning single chars)
        scanText(text, 'submit').then((result) => {
          if (result) updateTabIcon(result);
        });
      }
    }, DEBOUNCE_MS);
  });

  inputObserver.observe(element, {
    childList: true,
    characterData: true,
    subtree: true,
  });
}

// ─── Communication ───────────────────────────────────────────────────

/**
 * Sends text to the background service worker for scanning.
 * Returns the detection result or null on error.
 */
async function scanText(
  text: string,
  trigger: 'paste' | 'submit' | 'manual'
): Promise<DetectionResult | null> {
  lastScannedText = text;

  try {
    const message: ExtensionMessage = {
      type: 'SCAN_TEXT',
      payload: {
        text,
        sourceUrl: window.location.href,
        trigger,
      },
      timestamp: Date.now(),
    };

    const response = await chrome.runtime.sendMessage(message);
    return response as DetectionResult;
  } catch (error) {
    console.error('[ChatGPhish] Scan request failed:', error);
    return null;
  }
}

/**
 * Requests current extension settings from the service worker.
 */
async function requestSettings(): Promise<ExtensionSettings | null> {
  try {
    const message: ExtensionMessage = {
      type: 'GET_SETTINGS',
      timestamp: Date.now(),
    };
    const response = await chrome.runtime.sendMessage(message);
    return response as ExtensionSettings;
  } catch (error) {
    console.error('[ChatGPhish] Failed to load settings:', error);
    return null;
  }
}

/**
 * Notifies the service worker to update the extension icon
 * based on the latest scan result.
 */
function updateTabIcon(result: DetectionResult): void {
  chrome.runtime.sendMessage({
    type: 'UPDATE_ICON',
    payload: {
      threatLevel: result.threatLevel,
      tabId: null, // Service worker will determine from sender
    },
    timestamp: Date.now(),
  }).catch(() => {
    // Silently ignore — icon update is non-critical
  });
}

// ─── UI Helpers ──────────────────────────────────────────────────────

/**
 * Shows a toast notification in the page to alert the user
 * about a detected threat.
 *
 * The toast is injected directly into the page DOM as a
 * floating element positioned at the top-right corner.
 */
function showToast(config: ToastConfig): void {
  // Remove existing toast if present
  const existing = document.getElementById('chatgphish-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'chatgphish-toast';

  const colors: Record<string, { bg: string; border: string; icon: string }> = {
    clean: { bg: '#065f46', border: '#10b981', icon: '✅' },
    suspicious: { bg: '#92400e', border: '#f59e0b', icon: '⚡' },
    malicious: { bg: '#991b1b', border: '#ef4444', icon: '⚠️' },
    critical: { bg: '#7f1d1d', border: '#dc2626', icon: '🚨' },
  };

  const style = colors[config.threatLevel] ?? colors.suspicious;

  toast.style.cssText = `
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 999999;
    background: ${style.bg};
    border: 2px solid ${style.border};
    border-radius: 12px;
    padding: 16px 20px;
    max-width: 400px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    color: #ffffff;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    animation: chatgphish-slideIn 0.3s ease-out;
    cursor: pointer;
  `;

  const categoryLabels: Record<string, string> = {
    system_prompt_override: 'System Prompt Override',
    hidden_image: 'Hidden Tracking Pixel',
    suspicious_url: 'Suspicious URL',
    invisible_unicode: 'Invisible Characters',
    base64_payload: 'Encoded Payload',
    qr_code_injection: 'QR Code Injection',
    html_injection: 'HTML Injection',
    data_exfiltration: 'Data Exfiltration',
    social_engineering: 'Social Engineering',
    unknown: 'Unknown Threat',
  };

  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
      <span style="font-size:20px;">${style.icon}</span>
      <strong style="font-size:15px;">ChatGPhish Sanitizer</strong>
    </div>
    <div style="margin-bottom:6px;">
      <strong>${categoryLabels[config.category] ?? config.category}</strong>
    </div>
    <div style="opacity:0.85;font-size:13px;">
      Detected ${config.matchCount} threat${config.matchCount !== 1 ? 's' : ''}.
      ${config.wasCleaned ? 'Content has been cleaned.' : 'Submission blocked.'}
    </div>
  `;

  // Click to dismiss
  toast.addEventListener('click', () => toast.remove());

  document.body.appendChild(toast);

  // Auto-dismiss
  if (config.duration > 0) {
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s';
      setTimeout(() => toast.remove(), 300);
    }, config.duration);
  }

  // Inject animation keyframes
  if (!document.getElementById('chatgphish-styles')) {
    const styleEl = document.createElement('style');
    styleEl.id = 'chatgphish-styles';
    styleEl.textContent = `
      @keyframes chatgphish-slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(styleEl);
  }
}

// ─── Utility Functions ───────────────────────────────────────────────

/**
 * Gets the CSS selector for the input field on the current site.
 */
function getSelectorForCurrentSite(): string | null {
  const hostname = window.location.hostname;
  for (const [domain, selector] of Object.entries(SITE_SELECTORS)) {
    if (hostname.includes(domain)) return selector;
  }
  return null;
}

/**
 * Extracts current text from the LLM input field.
 */
function getCurrentInputText(): string {
  const selector = getSelectorForCurrentSite();
  if (!selector) return '';

  const input = document.querySelector(selector);
  if (!input) return '';

  // contenteditable divs
  if (input.getAttribute('contenteditable')) {
    return input.textContent ?? '';
  }

  // textarea / input elements
  return (input as HTMLTextAreaElement).value ?? '';
}

/**
 * Inserts cleaned text at the current cursor position in the input.
 * Handles both contenteditable divs and textarea elements.
 */
function insertTextAtCursor(text: string): void {
  const selector = getSelectorForCurrentSite();
  if (!selector) return;

  const input = document.querySelector(selector);
  if (!input) return;

  if (input.getAttribute('contenteditable')) {
    // For contenteditable, we need to manipulate the DOM directly
    input.textContent = text;
    // Dispatch input event to trigger framework reactivity
    input.dispatchEvent(new Event('input', { bubbles: true }));
  } else {
    const textarea = input as HTMLTextAreaElement;
    textarea.value = text;
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

// ─── Bootstrap ───────────────────────────────────────────────────────

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
