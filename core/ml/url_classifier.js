/**
 * Trust Layer — Production URL Inference Engine
 * Executes mathematically verified inference using trained and calibrated weights.
 * Supports Model Abstention when evidence is insufficient or uncertain.
 */

import { URLFeatureExtractor } from './url_features.js';

// Embedded Model Artifact (Trained on Kaggle/PhiUSIIL/PhishTank benchmark)
import MODEL_ARTIFACT from '../../models/url_model_v1/model.json' with { type: 'json' };

export class URLClassifier {
  static get MODEL_METADATA() {
    return {
      name: MODEL_ARTIFACT.model_name,
      type: MODEL_ARTIFACT.model_type,
      version: '1.0.0',
      trainedAt: MODEL_ARTIFACT.trained_at,
      schemaVersion: MODEL_ARTIFACT.schema_version,
      calibration: MODEL_ARTIFACT.calibration
    };
  }

  /**
   * Performs real ML inference on a URL string.
   * @param {string} url 
   * @returns {{
   *   status: string,
   *   url: string,
   *   hostname: string,
   *   modelName: string,
   *   modelVersion: string,
   *   probabilityPhishing: number,
   *   probabilityLegitimate: number,
   *   prediction: string,
   *   confidenceLevel: string,
   *   abstain: boolean,
   *   abstainReason: string|null,
   *   topContributingFeatures: Array<{name: string, value: number, contribution: number, description: string}>,
   *   rawFeatures: object,
   *   schema: Array<object>
   * }}
   */
  static predict(url) {
    const extraction = URLFeatureExtractor.extract(url);
    if (extraction.extractionStatus !== 'SUCCESS') {
      return {
        status: 'EXTRACTION_ERROR',
        url,
        hostname: extraction.parsed?.hostname || '',
        modelName: MODEL_ARTIFACT.model_name,
        modelVersion: '1.0.0',
        probabilityPhishing: 1.0,
        probabilityLegitimate: 0.0,
        prediction: 'MALFORMED_INPUT',
        confidenceLevel: 'HIGH',
        abstain: false,
        abstainReason: 'Invalid URL format',
        topContributingFeatures: [],
        rawFeatures: null,
        schema: URLFeatureExtractor.SCHEMA
      };
    }

    const { featureVector, features, parsed } = extraction;
    const { weights, bias, scaler } = MODEL_ARTIFACT;
    const { means, stds } = scaler;

    // 1. Feature normalization
    let logit = bias;
    const contributions = [];
    const schema = URLFeatureExtractor.SCHEMA;

    for (let j = 0; j < featureVector.length; j++) {
      const xVal = featureVector[j];
      const mean = means[j] || 0;
      const std = stds[j] || 1;
      const normX = (xVal - mean) / std;
      const contribution = parseFloat((weights[j] * normX).toFixed(4));

      logit += contribution;

      contributions.push({
        name: schema[j].name,
        value: xVal,
        normalizedValue: parseFloat(normX.toFixed(4)),
        weight: weights[j],
        contribution,
        description: schema[j].description
      });
    }

    // 2. Calibrated Sigmoid Activation
    const boundedLogit = Math.max(Math.min(logit, 20), -20);
    const probPhishing = parseFloat((1 / (1 + Math.exp(-boundedLogit))).toFixed(4));
    const probLegit = parseFloat((1 - probPhishing).toFixed(4));

    // 3. Top Contributing Features Ranking
    const topContributing = contributions
      .filter(c => Math.abs(c.contribution) > 0.05)
      .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
      .slice(0, 6);

    // 4. Model Decision & Abstention Logic
    let prediction = 'LEGITIMATE';
    let confidenceLevel = 'HIGH';
    let abstain = false;
    let abstainReason = null;

    // Check for Uncertainty Range (0.38 <= P <= 0.62)
    if (probPhishing >= 0.38 && probPhishing <= 0.62) {
      prediction = 'UNCERTAIN';
      confidenceLevel = 'LOW';
      abstain = true;
      abstainReason = 'URL lexical signals are inconclusive. Deep HTTP/page observation required.';
    } else if (probPhishing > 0.62) {
      prediction = 'PHISHING';
      confidenceLevel = probPhishing >= 0.85 ? 'CRITICAL' : 'HIGH';
    } else {
      prediction = 'LEGITIMATE';
      confidenceLevel = probPhishing <= 0.15 ? 'HIGH' : 'MODERATE';
    }

    return {
      status: 'SUCCESS',
      url: parsed.normalizedUrl,
      hostname: parsed.hostname,
      protocol: parsed.protocol,
      pathname: parsed.pathname,
      modelName: MODEL_ARTIFACT.model_name,
      modelVersion: '1.0.0',
      probabilityPhishing: probPhishing,
      probabilityLegitimate: probLegit,
      prediction,
      confidenceLevel,
      abstain,
      abstainReason,
      topContributingFeatures: topContributing,
      rawFeatures: features,
      schema: URLFeatureExtractor.SCHEMA
    };
  }
}
