/**
 * Core type definitions for ChatGPhish Sanitizer.
 *
 * These interfaces define the contract between all extension components:
 * content script, background service worker, popup UI, and ML classifier.
 */

/**
 * Severity level for detected threats.
 * Maps to icon states and notification urgency.
 */
export type ThreatLevel = 'clean' | 'suspicious' | 'malicious' | 'critical';

/**
 * Category of XPIA attack pattern detected.
 * Each category requires different mitigation strategy.
 */
export type ThreatCategory =
  | 'system_prompt_override'   // "Ignore previous instructions..."
  | 'hidden_image'             // Tracking pixels disguised as images
  | 'suspicious_url'           // URL shorteners, IP-based, known phishing
  | 'invisible_unicode'        // Zero-width chars, direction overrides
  | 'base64_payload'           // Encoded payloads hidden in text
  | 'qr_code_injection'        // QR codes as data URIs
  | 'html_injection'           // Raw HTML embedded in markdown
  | 'data_exfiltration'        // Patterns that leak user data
  | 'social_engineering'       // Phishing-style urgency/fear tactics
  | 'unknown';                 // ML-flagged but no regex match

/**
 * Result of pattern matching against a single regex rule.
 */
export interface PatternMatch {
  /** Which pattern category was matched */
  category: ThreatCategory;
  /** Human-readable description of what was found */
  description: string;
  /** The actual text substring that triggered the match */
  matchedText: string;
  /** Regex pattern that matched */
  patternName: string;
  /** Severity of this specific match (0.0 to 1.0) */
  severity: number;
  /** Start index in the original text */
  startIndex: number;
  /** End index in the original text */
  endIndex: number;
}

/**
 * Complete result from scanning text for XPIA threats.
 * Returned by both patternDetector and the ensemble engine.
 */
export interface DetectionResult {
  /** Whether any threat was detected */
  isMalicious: boolean;
  /** Overall threat level (highest among all matches) */
  threatLevel: ThreatLevel;
  /** Primary (highest severity) threat category */
  primaryCategory: ThreatCategory;
  /** Combined confidence score (0.0 to 1.0) */
  confidence: number;
  /** All individual pattern matches found */
  matches: PatternMatch[];
  /** Score breakdown for transparency */
  scores: {
    /** Regex pattern detector score (0.0 to 1.0) */
    regexScore: number;
    /** ML classifier score (0.0 to 1.0) */
    mlScore: number;
    /** Final ensemble score (weighted average) */
    ensembleScore: number;
  };
  /** Cleaned text with malicious content removed */
  cleanedText: string;
  /** Timestamp of the scan */
  scannedAt: number;
}

/**
 * Scan statistics stored in chrome.storage.local.
 * Used by popup UI to display usage metrics.
 */
export interface ScanStats {
  /** Total number of texts scanned */
  totalScans: number;
  /** Number of threats detected and blocked */
  threatsBlocked: number;
  /** Breakdown by threat category */
  threatsByCategory: Record<ThreatCategory, number>;
  /** Daily scan counts (last 30 days, ISO date -> count) */
  dailyScans: Record<string, number>;
  /** Average inference time in milliseconds */
  avgInferenceTime: number;
  /** Last scan timestamp */
  lastScanAt: number | null;
}

/**
 * User-configurable extension settings.
 * Stored in chrome.storage.sync for cross-device sync.
 */
export interface ExtensionSettings {
  /** Master on/off toggle */
  enabled: boolean;
  /** Detection sensitivity: 0.0 (lenient) to 1.0 (strict) */
  sensitivity: number;
  /** Whether to use ML model for classification */
  useMLModel: boolean;
  /** Weight of regex score in ensemble (ML weight = 1 - this) */
  regexWeight: number;
  /** Show toast notifications on detection */
  showNotifications: boolean;
  /** Auto-clean malicious content from pasted text */
  autoCleanEnabled: boolean;
  /** Block submission if threat detected */
  blockOnThreat: boolean;
  /** Minimum threat level to trigger block: 'suspicious' | 'malicious' | 'critical' */
  blockThreshold: ThreatLevel;
  /** Enable debug logging to console */
  debugMode: boolean;
  /** Preferred language for UI */
  language: 'en' | 'ru';
}

/**
 * Default settings applied on first install.
 */
export const DEFAULT_SETTINGS: ExtensionSettings = {
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

/**
 * Message types exchanged between content script and service worker.
 */
export type MessageType =
  | 'SCAN_TEXT'           // Content -> Background: scan text for threats
  | 'SCAN_RESULT'         // Background -> Content: detection result
  | 'GET_STATS'           // Popup -> Background: request scan stats
  | 'STATS_RESPONSE'      // Background -> Popup: stats data
  | 'GET_SETTINGS'        // Any -> Background: request current settings
  | 'SETTINGS_RESPONSE'   // Background -> Any: current settings
  | 'UPDATE_SETTINGS'     // Options -> Background: save new settings
  | 'UPDATE_ICON'         // Background -> Content: update extension icon state
  | 'SHOW_TOAST';         // Background -> Content: display toast notification

/**
 * Message envelope for chrome.runtime.sendMessage communication.
 */
export interface ExtensionMessage {
  type: MessageType;
  payload?: unknown;
  timestamp: number;
}

/**
 * SCAN_TEXT message payload sent from content script.
 */
export interface ScanTextPayload {
  /** The text to analyze */
  text: string;
  /** Source URL where the text was found */
  sourceUrl: string;
  /** Event that triggered the scan */
  trigger: 'paste' | 'submit' | 'manual';
}

/**
 * Icon state for the extension toolbar icon.
 * Reflects the current security status of the active tab.
 */
export type IconState = 'inactive' | 'clean' | 'suspicious' | 'malicious';

/**
 * Per-tab state tracked by the service worker.
 */
export interface TabState {
  /** Current icon state */
  iconState: IconState;
  /** Last scan result for this tab */
  lastResult: DetectionResult | null;
  /** Number of scans performed on this tab */
  scanCount: number;
}

/**
 * Regex pattern definition used by the pattern detector.
 */
export interface PatternDefinition {
  /** Unique identifier for this pattern */
  name: string;
  /** The regex to test against */
  regex: RegExp;
  /** Threat category this pattern detects */
  category: ThreatCategory;
  /** Base severity score (0.0 to 1.0) */
  severity: number;
  /** Human-readable description */
  description: string;
  /** Example malicious input that triggers this pattern */
  example: string;
}

/**
 * ML classifier inference result.
 */
export interface MLClassifierResult {
  /** Whether the model considers input malicious */
  isMalicious: boolean;
  /** Confidence score from the model (0.0 to 1.0) */
  confidence: number;
  /** Inference time in milliseconds */
  inferenceTime: number;
  /** Whether the model was successfully loaded */
  modelLoaded: boolean;
}

/**
 * Toast notification configuration.
 */
export interface ToastConfig {
  /** Threat level to display */
  threatLevel: ThreatLevel;
  /** Primary category detected */
  category: ThreatCategory;
  /** Number of matches found */
  matchCount: number;
  /** Whether auto-clean was applied */
  wasCleaned: boolean;
  /** Auto-dismiss after milliseconds (0 = manual dismiss) */
  duration: number;
}
