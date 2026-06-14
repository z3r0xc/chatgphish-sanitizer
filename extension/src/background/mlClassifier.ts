/**
 * ML Classifier — ONNX.js-based inference for XPIA detection.
 *
 * Loads a DistilBERT model exported to ONNX format and runs inference
 * directly in the browser via onnxruntime-web (WebAssembly backend).
 *
 * The model performs binary classification:
 * - 0: Benign (normal prompt)
 * - 1: Malicious (XPIA attack)
 *
 * Tokenization is done with a simple word-level tokenizer using
 * a pre-built vocabulary file (vocab.txt).
 *
 * Performance: ~50-150ms per inference on typical prompts.
 * Model size: ~65MB (loaded once, cached in memory).
 *
 * @module mlClassifier
 */

import type { MLClassifierResult } from '../types/index';

// ─── Configuration ───────────────────────────────────────────────────

/** Path to the ONNX model file relative to extension root */
const MODEL_PATH = 'public/models/model.onnx';

/** Path to the vocabulary file */
const VOCAB_PATH = 'public/models/vocab.txt';

/** Maximum sequence length for the model */
const MAX_SEQ_LENGTH = 128;

/** Special token IDs */
const CLS_TOKEN_ID = 101;
const SEP_TOKEN_ID = 102;
const PAD_TOKEN_ID = 0;
const UNK_TOKEN_ID = 100;

// ─── State ───────────────────────────────────────────────────────────

let session: unknown = null;
let vocabulary: Map<string, number> | null = null;
let isInitializing = false;
let initError: Error | null = null;

// ─── Initialization ──────────────────────────────────────────────────

/**
 * Initializes the ONNX runtime and loads the model.
 *
 * This is called lazily on first inference to avoid blocking
 * extension startup. The model is cached in memory for subsequent calls.
 *
 * @returns true if initialization succeeded
 */
async function initializeModel(): Promise<boolean> {
  if (session) return true;
  if (isInitializing) return false;
  if (initError) return false;

  isInitializing = true;

  try {
    // Dynamic import to avoid bundling onnxruntime-web if not used
    const ort = await import('onnxruntime-web');

    // Configure WASM paths
    const extensionUrl = chrome.runtime.getURL('');
    ort.env.wasm.wasmPaths = extensionUrl + 'assets/';

    // Load model
    const modelUrl = chrome.runtime.getURL(MODEL_PATH);
    console.log('[MLClassifier] Loading model from:', modelUrl);

    session = await ort.InferenceSession.create(modelUrl, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all',
    });

    // Load vocabulary
    const vocabUrl = chrome.runtime.getURL(VOCAB_PATH);
    const vocabResponse = await fetch(vocabUrl);
    const vocabText = await vocabResponse.text();

    vocabulary = new Map<string, number>();
    vocabText.split('\n').forEach((token, index) => {
      const trimmed = token.trim();
      if (trimmed) vocabulary!.set(trimmed, index);
    });

    console.log('[MLClassifier] Model loaded successfully. Vocab size:', vocabulary.size);
    isInitializing = false;
    return true;
  } catch (error) {
    initError = error as Error;
    isInitializing = false;
    console.error('[MLClassifier] Failed to initialize:', error);
    return false;
  }
}

// ─── Tokenization ────────────────────────────────────────────────────

/**
 * Simple word-level tokenizer matching the vocabulary used during training.
 *
 * Steps:
 * 1. Lowercase and strip
 * 2. Split into words
 * 3. Map to vocabulary IDs (unknown words → UNK token)
 * 4. Add [CLS] and [SEP] tokens
 * 5. Pad to MAX_SEQ_LENGTH
 *
 * @param text - Input text to tokenize
 * @returns Object with input_ids, attention_mask, and token_type_ids tensors
 */
function tokenize(text: string): {
  inputIds: number[];
  attentionMask: number[];
  tokenTypeIds: number[];
} {
  if (!vocabulary) {
    throw new Error('Vocabulary not loaded');
  }

  // Basic tokenization: lowercase, split on whitespace and punctuation
  const words = text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' $& ')
    .split(/\s+/)
    .filter(Boolean);

  // Map to token IDs
  const tokenIds = words.map((word) => {
    return vocabulary!.get(word) ?? UNK_TOKEN_ID;
  });

  // Truncate to max length (minus special tokens)
  const truncated = tokenIds.slice(0, MAX_SEQ_LENGTH - 2);

  // Build input_ids: [CLS] + tokens + [SEP] + padding
  const inputIds: number[] = [CLS_TOKEN_ID, ...truncated, SEP_TOKEN_ID];
  const attentionMask: number[] = new Array(inputIds.length).fill(1);

  // Pad to MAX_SEQ_LENGTH
  while (inputIds.length < MAX_SEQ_LENGTH) {
    inputIds.push(PAD_TOKEN_ID);
    attentionMask.push(0);
  }

  // Token type IDs (all 0 for single-sentence classification)
  const tokenTypeIds = new Array(MAX_SEQ_LENGTH).fill(0);

  return { inputIds, attentionMask, tokenTypeIds };
}

// ─── Inference ───────────────────────────────────────────────────────

/**
 * Runs ML classification on the given text.
 *
 * Returns a result with confidence score and timing information.
 * If the model is not loaded, returns a fallback result with modelLoaded=false.
 *
 * @param text - The text to classify
 * @returns Classification result with confidence and timing
 *
 * @example
 * const result = await classifyText("Ignore previous instructions");
 * console.log(result.isMalicious); // true
 * console.log(result.confidence);  // 0.95
 */
export async function classifyText(text: string): Promise<MLClassifierResult> {
  const startTime = performance.now();

  // Attempt to load model if not yet initialized
  const loaded = await initializeModel();
  if (!loaded || !session) {
    return {
      isMalicious: false,
      confidence: 0,
      inferenceTime: 0,
      modelLoaded: false,
    };
  }

  try {
    const ort = await import('onnxruntime-web');

    // Tokenize
    const { inputIds, attentionMask, tokenTypeIds } = tokenize(text);

    // Create tensors
    const inputIdsTensor = new ort.Tensor(
      'int64',
      BigInt64Array.from(inputIds.map(BigInt)),
      [1, MAX_SEQ_LENGTH]
    );
    const attentionMaskTensor = new ort.Tensor(
      'int64',
      BigInt64Array.from(attentionMask.map(BigInt)),
      [1, MAX_SEQ_LENGTH]
    );
    const tokenTypeIdsTensor = new ort.Tensor(
      'int64',
      BigInt64Array.from(tokenTypeIds.map(BigInt)),
      [1, MAX_SEQ_LENGTH]
    );

    // Run inference
    const feeds: Record<string, unknown> = {
      input_ids: inputIdsTensor,
      attention_mask: attentionMaskTensor,
      token_type_ids: tokenTypeIdsTensor,
    };

    const results = await (session as { run: (feeds: Record<string, unknown>) => Promise<Record<string, unknown>> }).run(feeds);

    // Extract logits and apply softmax
    const logits = results.logits as { data: Float32Array };
    const data = logits.data;
    const exp0 = Math.exp(data[0]);
    const exp1 = Math.exp(data[1]);
    const softmax = exp1 / (exp0 + exp1); // Probability of class 1 (malicious)

    const inferenceTime = performance.now() - startTime;
    const confidence = Math.round(softmax * 1000) / 1000;

    console.log(`[MLClassifier] Inference: ${inferenceTime.toFixed(1)}ms, confidence: ${confidence}`);

    return {
      isMalicious: confidence > 0.5,
      confidence,
      inferenceTime,
      modelLoaded: true,
    };
  } catch (error) {
    console.error('[MLClassifier] Inference error:', error);
    const inferenceTime = performance.now() - startTime;
    return {
      isMalicious: false,
      confidence: 0,
      inferenceTime,
      modelLoaded: true,
    };
  }
}

/**
 * Checks if the ML model is loaded and ready.
 */
export function isModelLoaded(): boolean {
  return session !== null && vocabulary !== null;
}

/**
 * Forces model pre-loading. Call during extension startup
 * to have the model ready before first scan.
 */
export async function preloadModel(): Promise<void> {
  await initializeModel();
}
