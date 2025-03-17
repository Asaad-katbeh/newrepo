/**
 * @fileoverview Logging utility for the security review bot.
 * Provides structured logging with different severity levels and specialized logging methods.
 */

const winston = require("winston");
const config = require("./config");

/**
 * @class Logger
 * @description Handles all logging operations for the security review bot with support for
 * console and file outputs, structured logging, and environment-specific configurations.
 */
class Logger {
  /**
   * @constructor
   * @description Initializes the logger with console and optional file transports.
   * Configures logging format, metadata, and transport options based on the environment.
   */
  constructor() {
    this.logger = winston.createLogger({
      level: config.config.logging?.level || "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: {
        service: "security-review-bot",
        environment: process.env.NODE_ENV || "development",
        repository: process.env.GITHUB_REPOSITORY,
        event: process.env.GITHUB_EVENT_NAME,
        workflow: process.env.GITHUB_WORKFLOW,
        run_id: process.env.GITHUB_RUN_ID,
      },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
        }),
        new winston.transports.File({
          filename: "./security-bot.log",
          maxsize: config.config.logging?.max_size || 10485760, // 10MB
          maxFiles: config.config.logging?.max_files || 5,
        }),
        new winston.transports.File({
          filename: "./error.log",
          level: "error",
          maxsize: config.config.logging?.max_size || 10485760, // 10MB
          maxFiles: 3,
        }),
      ],
    });
  }

  /**
   * @method info
   * @description Logs an informational message
   * @param {string} message - The message to log
   * @param {Object} [meta={}] - Additional metadata to include in the log entry
   */
  info(message, meta = {}) {
    this.logger.info(message, meta);
  }

  /**
   * @method error
   * @description Logs an error message
   * @param {string} message - The error message to log
   * @param {Object} [meta={}] - Additional metadata to include in the log entry
   */
  error(message, meta = {}) {
    this.logger.error(message, meta);
  }

  /**
   * @method debug
   * @description Logs a debug message
   * @param {string} message - The debug message to log
   * @param {Object} [meta={}] - Additional metadata to include in the log entry
   */
  debug(message, meta = {}) {
    this.logger.debug(message, meta);
  }

  /**
   * @method warn
   * @description Logs a warning message
   * @param {string} message - The warning message to log
   * @param {Object} [meta={}] - Additional metadata to include in the log entry
   */
  warn(message, meta = {}) {
    this.logger.warn(message, meta);
  }

  /**
   * @method logVulnerability
   * @description Logs a detected security vulnerability with detailed information
   * @param {Object} vulnerability - The vulnerability object to log
   * @param {number} prNumber - Pull request number where the vulnerability was found
   */
  logVulnerability(vulnerability, prNumber) {
    this.info("Vulnerability detected", {
      prNumber,
      vulnerability: {
        type: vulnerability.type,
        severity: vulnerability.severity,
        confidence: vulnerability.confidence,
        owasp: vulnerability.owasp,
        cwe: vulnerability.cwe,
        location: vulnerability.location,
        description: vulnerability.description,
        suggestedFix: vulnerability.suggestedFix,
        timestamp: new Date().toISOString(),
        commit: process.env.GITHUB_SHA,
        branch: process.env.GITHUB_REF,
      },
    });
  }

  /**
   * @method logFalsePositive
   * @description Logs when a vulnerability is marked as a false positive
   * @param {number} prNumber - Pull request number
   * @param {string} issueId - Identifier of the false positive issue
   * @param {string} comment - The comment that marked this as false positive
   */
  logFalsePositive(prNumber, issueId, comment) {
    this.info("False positive marked", {
      prNumber,
      issueId,
      comment,
      timestamp: new Date().toISOString(),
      markedBy: process.env.GITHUB_ACTOR,
    });
  }

  /**
   * @method logApiError
   * @description Logs an API error with detailed context and stack trace
   * @param {Error} error - The error object
   * @param {Object} context - Context information about where the error occurred
   */
  logApiError(error, context) {
    this.error("API request failed", {
      error: error.message,
      context,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      endpoint: context.endpoint,
    });
  }

  /**
   * @method logScanStart
   * @description Logs the start of a security scan with configuration details
   * @param {number} prNumber - Pull request number being scanned
   */
  logScanStart(prNumber) {
    this.info("Starting security scan", {
      prNumber,
      timestamp: new Date().toISOString(),
      configuration: {
        confidenceThreshold: config.getConfidenceThreshold(),
        maxLines: config.getMaxLines(),
        enabledChecks: Object.entries(config.getSecurityChecks())
          .filter(([_, check]) => check.enabled)
          .map(([name, _]) => name),
        severityLevels: Object.entries(config.getSeverityLevels())
          .filter(([_, level]) => level.enabled)
          .map(([name, _]) => name),
      },
    });
  }

  /**
   * @method logScanComplete
   * @description Logs the completion of a security scan with summary information
   * @param {number} prNumber - Pull request number that was scanned
   * @param {number} vulnerabilityCount - Number of vulnerabilities found
   */
  logScanComplete(prNumber, vulnerabilityCount) {
    this.info("Security scan completed", {
      prNumber,
      vulnerabilityCount,
      timestamp: new Date().toISOString(),
      duration: process.uptime(),
    });
  }
}

module.exports = new Logger();
