const yaml = require("js-yaml");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

/**
 * @class Config
 * @description Configuration manager for the security review bot.
 * Handles loading and validation of configuration from YAML files.
 */
class Config {
  /**
   * @constructor
   * @description Initializes the configuration by loading and validating the config file
   * @throws {Error} If configuration file is not found or validation fails
   */
  constructor() {
    this.config = this.loadConfig();
    this.validateConfig();
  }

  /**
   * @private
   * @description Loads configuration from YAML file based on environment
   * @returns {Object} Parsed configuration object
   * @throws {Error} If configuration file cannot be found or parsed
   */
  loadConfig() {
    try {
      // Try to load from GitHub Actions environment first
      if (process.env.GITHUB_ACTIONS === "true") {
        const configPath =
          process.env.CONFIG_PATH || "config/securitybot-config.yml";
        const configContent = fs.readFileSync(configPath, "utf8");
        return yaml.load(configContent);
      }

      // For local development, try to load from local file
      const configPath = path.join(
        process.cwd(),
        "config",
        "securitybot-config.yml"
      );
      if (fs.existsSync(configPath)) {
        const configContent = fs.readFileSync(configPath, "utf8");
        return yaml.load(configContent);
      }

      throw new Error("Configuration file not found");
    } catch (error) {
      console.error("Error loading configuration:", error);
      throw error;
    }
  }

  /**
   * @private
   * @description Validates the loaded configuration
   * @throws {Error} If any required fields are missing or invalid
   */
  validateConfig() {
    const requiredFields = [
      "confidence_threshold",
      "security_checks",
      "severity_levels",
      "max_lines",
      "max_retries",
      "api_timeout",
      "ai_model",
    ];

    for (const field of requiredFields) {
      if (!this.config[field]) {
        throw new Error(`Missing required config field: ${field}`);
      }
    }

    // Validate AI model config
    const aiConfig = this.config.ai_model;
    if (!aiConfig.provider || !aiConfig.model) {
      throw new Error("Missing required AI model configuration");
    }

    // Validate confidence threshold
    if (
      this.config.confidence_threshold < 0 ||
      this.config.confidence_threshold > 1
    ) {
      throw new Error("Confidence threshold must be between 0 and 1");
    }

    // Validate security checks
    for (const [check, settings] of Object.entries(
      this.config.security_checks
    )) {
      if (!settings.enabled) continue;

      if (!settings.owasp || !settings.cwe) {
        throw new Error(
          `Missing OWASP or CWE reference for security check: ${check}`
        );
      }
    }

    // Validate severity levels
    for (const [level, settings] of Object.entries(
      this.config.severity_levels
    )) {
      if (!settings.enabled) continue;

      if (settings.threshold < 0 || settings.threshold > 1) {
        throw new Error(`Invalid threshold for severity level: ${level}`);
      }
    }
  }

  /**
   * @description Gets the configured security checks
   * @returns {Object} Security checks configuration
   */
  getSecurityChecks() {
    return this.config.security_checks;
  }

  /**
   * @description Gets the configured severity levels
   * @returns {Object} Severity levels configuration
   */
  getSeverityLevels() {
    return this.config.severity_levels;
  }

  /**
   * @description Gets the configured confidence threshold
   * @returns {number} Confidence threshold value between 0 and 1
   */
  getConfidenceThreshold() {
    return this.config.confidence_threshold;
  }

  /**
   * @description Gets the maximum number of lines to analyze
   * @returns {number} Maximum lines configuration value
   */
  getMaxLines() {
    return this.config.max_lines;
  }

  /**
   * @description Gets the maximum number of API retries
   * @returns {number} Maximum retries configuration value
   */
  getMaxRetries() {
    return this.config.max_retries;
  }

  /**
   * @description Gets the API timeout in milliseconds
   * @returns {number} API timeout configuration value
   */
  getApiTimeout() {
    return this.config.api_timeout;
  }

  /**
   * @description Gets the AI model configuration
   * @returns {Object} AI model configuration object containing provider and model settings
   */
  getAiModelConfig() {
    return this.config.ai_model;
  }

  /**
   * @description Gets the false positive handling configuration
   * @returns {Object} False positive configuration with default enabled value if not set
   */
  getFalsePositiveConfig() {
    return (
      this.config.false_positive || {
        enabled: true,
        command: "@[Ss]ecurity[Bb]ot false-positive",
        storage: "comments",
        expiration: 30,
        require_approval: true,
        track_history: true,
        include_reason: true,
      }
    );
  }

  /**
   * @description Gets the re-evaluation configuration
   * @returns {Object} Re-evaluation configuration with default enabled value if not set
   */
  getReevaluationConfig() {
    return this.config.reevaluation || { enabled: true };
  }

  /**
   * @description Gets the logging configuration
   * @returns {Object} Logging configuration with default values if not set
   */
  getLoggingConfig() {
    return (
      this.config.logging || {
        level: "info",
        include_metadata: true,
        include_api_calls: true,
      }
    );
  }
}

module.exports = new Config();
