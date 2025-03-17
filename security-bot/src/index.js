/**
 * @fileoverview Main implementation of the security review bot.
 * Handles PR analysis, vulnerability detection, and GitHub interactions.
 */

const { Octokit } = require("@octokit/rest");
const OpenAI = require("openai");
const config = require("./config");
const logger = require("./logger");
const fs = require("fs");

/**
 * @type {Octokit}
 * @description GitHub API client instance
 */
const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
  request: {
    timeout: config.getApiTimeout(),
  },
});

/**
 * @type {OpenAI}
 * @description OpenAI API client instance
 */
const aiConfig = config.getAiModelConfig();
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: config.getApiTimeout(),
});

/**
 * @type {Map<string, Object>}
 * @description Stores false positive reports with their metadata
 */
const falsePositives = new Map();

/**
 * @class APIError
 * @extends Error
 * @description Custom error class for API-related errors with retry information
 */
class APIError extends Error {
  /**
   * @constructor
   * @param {string} message - Error message
   * @param {string} type - Type of API error
   * @param {boolean} [retryable=false] - Whether the error can be retried
   */
  constructor(message, type, retryable = false) {
    super(message);
    this.name = "APIError";
    this.type = type;
    this.retryable = retryable;
  }
}

/**
 * @async
 * @function handleAPIError
 * @description Handles API errors by logging and posting error comments to PR
 * @param {Error} error - The error that occurred
 * @param {number} prNumber - Pull request number
 * @param {string} context - Context where the error occurred
 * @returns {Promise<boolean>} Whether the error is retryable
 */
async function handleAPIError(error, prNumber, context) {
  let errorMessage = "## ⚠️ API Error\n\n";
  let isRetryable = false;

  if (error.response) {
    switch (error.response.status) {
      case 401:
        errorMessage +=
          "Authentication failed. Please check the API credentials.";
        break;
      case 403:
        errorMessage += "Access denied. Please check the permissions.";
        break;
      case 429:
        errorMessage += "Rate limit exceeded. Please try again later.";
        isRetryable = true;
        break;
      case 500:
      case 502:
      case 503:
      case 504:
        errorMessage +=
          "Service temporarily unavailable. Please try again later.";
        isRetryable = true;
        break;
      default:
        errorMessage += `API request failed with status ${error.response.status}.`;
    }
  } else if (error.request) {
    errorMessage +=
      "No response received from the API. Please check your network connection.";
    isRetryable = true;
  } else {
    errorMessage +=
      "Failed to make API request. Please check the configuration.";
  }

  errorMessage += `\n\n**Context:** ${context}`;
  errorMessage += "\n\n**Error Details:**";
  errorMessage += `\n\`\`\`\n${error.message}\n\`\`\``;

  logger.logApiError(error, context);

  try {
    await octokit.issues.createComment({
      owner: process.env.GITHUB_REPOSITORY.split("/")[0],
      repo: process.env.GITHUB_REPOSITORY.split("/")[1],
      issue_number: prNumber,
      body: errorMessage,
    });
  } catch (commentError) {
    logger.error("Failed to post error comment:", commentError);
  }

  return isRetryable;
}

/**
 * @async
 * @function retryWithBackoff
 * @description Retries an operation with exponential backoff
 * @param {Function} operation - Async operation to retry
 * @param {number} [maxRetries=3] - Maximum number of retry attempts
 * @param {number} [initialDelay=1000] - Initial delay in milliseconds
 * @returns {Promise<any>} Result of the operation
 * @throws {Error} Last error encountered if all retries fail
 */
async function retryWithBackoff(
  operation,
  maxRetries = 3,
  initialDelay = 1000
) {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      if (!error.retryable || attempt === maxRetries) {
        throw error;
      }

      const delay = initialDelay * Math.pow(2, attempt - 1);
      logger.info(
        `Retrying operation (attempt ${attempt}/${maxRetries}) after ${delay}ms`
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}

/**
 * @async
 * @function loadFalsePositives
 * @description Loads existing false positive reports from PR comments
 * @param {number} prNumber - Pull request number
 */
async function loadFalsePositives(prNumber) {
  try {
    const fpConfig = config.getFalsePositiveConfig();
    logger.debug("False positive config:", {
      enabled: fpConfig.enabled,
      command: fpConfig.command,
      require_approval: fpConfig.require_approval,
    });

    if (!fpConfig.enabled) {
      logger.info("False positive handling is disabled");
      return;
    }

    const { data: comments } = await octokit.issues.listComments({
      owner: process.env.GITHUB_REPOSITORY.split("/")[0],
      repo: process.env.GITHUB_REPOSITORY.split("/")[1],
      issue_number: prNumber,
      per_page: 100,
    });

    // Make the command pattern more robust
    const commandRegex = new RegExp(fpConfig.command + "\\s+(.+)$", "mi");

    logger.debug("Loading false positives from comments:", {
      totalComments: comments.length,
      commandPattern: fpConfig.command,
      regexPattern: commandRegex.toString(),
      comments: comments.map((c) => ({
        body: c.body,
        user: c.user.login,
        created_at: c.created_at,
      })),
    });

    for (const comment of comments) {
      logger.debug("Processing comment:", {
        body: comment.body,
        user: comment.user.login,
        created_at: comment.created_at,
      });

      const match = comment.body.match(commandRegex);
      if (match) {
        const issueId = match[1].trim();
        const fpKey = `${prNumber}-${issueId}`;

        logger.debug("Found false positive command:", {
          comment: comment.body,
          issueId,
          fpKey,
          user: comment.user.login,
          match: match[0],
        });

        if (fpConfig.require_approval) {
          const { data: user } = await octokit.rest.users.getByUsername({
            username: comment.user.login,
          });

          logger.debug("Checking user permissions:", {
            username: comment.user.login,
            isSiteAdmin: user.site_admin,
            hasOrganizations: !!user.organizations_url,
          });

          if (!user.site_admin && !user.organizations_url) {
            logger.warn(
              `False positive marked by non-maintainer: ${comment.user.login}`
            );
            continue;
          }
        }

        falsePositives.set(fpKey, {
          timestamp: new Date(comment.created_at).getTime(),
          comment: comment.body,
          markedBy: comment.user.login,
        });

        logger.logFalsePositive(prNumber, issueId, comment.body);
      } else {
        logger.debug("Comment did not match false positive pattern:", {
          comment: comment.body,
          pattern: commandRegex.toString(),
        });
      }
    }

    logger.debug("Loaded false positives:", {
      totalFalsePositives: falsePositives.size,
      keys: Array.from(falsePositives.keys()),
    });
  } catch (error) {
    logger.error("Error loading false positives:", error);
  }
}

/**
 * @async
 * @function processNewComments
 * @description Processes new comments for false positive commands
 * @param {number} prNumber - Pull request number
 */
async function processNewComments(prNumber) {
  try {
    const fpConfig = config.getFalsePositiveConfig();
    if (!fpConfig.enabled) return;

    const { data: comments } = await octokit.issues.listComments({
      owner: process.env.GITHUB_REPOSITORY.split("/")[0],
      repo: process.env.GITHUB_REPOSITORY.split("/")[1],
      issue_number: prNumber,
      per_page: 10,
    });

    const commandRegex = new RegExp(fpConfig.command + "\\s+(.+)$", "mi");

    for (const comment of comments) {
      const match = comment.body.match(commandRegex);
      if (match) {
        const issueId = match[1].trim();

        if (fpConfig.require_approval) {
          const { data: user } = await octokit.rest.users.getByUsername({
            username: comment.user.login,
          });

          if (!user.site_admin && !user.organizations_url) {
            logger.warn(
              `False positive marked by non-maintainer: ${comment.user.login}`
            );
            continue;
          }
        }

        await handleFalsePositive(prNumber, issueId, comment.body);
      }
    }
  } catch (error) {
    logger.error("Error processing new comments:", error);
  }
}

/**
 * @async
 * @function analyzeCodeDiff
 * @description Analyzes code diff for security vulnerabilities using AI
 * @param {string} diff - Code diff to analyze
 * @param {number} prNumber - Pull request number
 * @returns {Promise<Array<Object>>} Array of detected vulnerabilities
 */
async function analyzeCodeDiff(diff, prNumber) {
  const securityChecks = config.getSecurityChecks();
  const severityLevels = config.getSeverityLevels();
  const confidenceThreshold = config.getConfidenceThreshold();

  // Get list of false positive types for this PR
  const fpTypes = Array.from(falsePositives.entries())
    .filter(([key]) => key.startsWith(`${prNumber}-`))
    .map(([key]) => key.replace(`${prNumber}-`, ""));

  logger.debug("Starting code analysis with diff:", {
    diffLength: diff.length,
    confidenceThreshold,
    enabledChecks: Object.entries(securityChecks)
      .filter(([_, check]) => check.enabled)
      .map(([name, _]) => name),
    falsePositiveTypes: fpTypes,
    falsePositiveKeys: Array.from(falsePositives.keys()),
  });

  const prompt = `You are a security expert analyzing code for vulnerabilities. Review the following code diff and identify any security issues.

CRITICAL: FALSE POSITIVE HANDLING
The following vulnerability types have been explicitly marked as false positives and MUST be completely ignored in your analysis, regardless of any other factors:
${fpTypes.length > 0 ? fpTypes.map((type) => `- ${type}`).join("\n") : "None"}

IMPORTANT: If you detect any of these vulnerability types, you MUST NOT report them, even if:
- The confidence score is high
- The vulnerability is clearly present
- The code matches known patterns
- The severity is critical
- The vulnerability is in a different location
- The vulnerability type matches exactly (case-insensitive)

Security Checks to Consider:
${Object.entries(securityChecks)
  .filter(([_, check]) => check.enabled)
  .map(
    ([name, check]) => `
* ${name}
  - Description: ${check.description}
  - OWASP: ${check.owasp}
  - CWE: ${check.cwe}
  - Severity: ${check.severity}
  - Patterns: ${check.patterns ? check.patterns.join(", ") : "N/A"}
`
  )
  .join("\n")}

For each vulnerability found, provide the following information in a structured format:

Type of vulnerability: [Specify the type]
Severity: [critical/high/medium/low]
Confidence score: [0-1]
OWASP reference: [OWASP ID]
CWE reference: [CWE ID]
Location in code: [File and line numbers]
Description: [Detailed description of the vulnerability]
Suggested fix: [Code or description of how to fix]

Requirements:
- Only report vulnerabilities with confidence score >= ${confidenceThreshold}
- Be specific about the location of each vulnerability
- Provide actionable fix suggestions
- If no vulnerabilities are found, explicitly state that
- Format the location as "file.js:line" (e.g., "server.js:15")
- REMEMBER: Do not report ANY vulnerabilities that match the false positive types listed above, regardless of case
- If you detect a vulnerability that matches any of the false positive types (case-insensitive), you MUST skip it

Code diff to analyze:
\`\`\`diff
${diff}
\`\`\``;

  try {
    logger.debug("Sending analysis request to OpenAI");

    const response = await retryWithBackoff(
      async () => {
        const result = await openai.chat.completions.create({
          model: aiConfig.model,
          messages: [
            {
              role: "system",
              content: aiConfig.system_prompt,
            },
            {
              role: "user",
              content: prompt,
            },
          ],
          temperature: aiConfig.temperature,
          max_tokens: aiConfig.max_tokens,
        });
        return result;
      },
      config.getMaxRetries(),
      config.getApiTimeout()
    );

    if (!response?.choices?.[0]?.message?.content) {
      throw new Error("Invalid response from OpenAI API");
    }

    logger.debug("Received OpenAI response:", {
      responseLength: response.choices[0].message.content.length,
      preview: response.choices[0].message.content.substring(0, 200) + "...",
    });

    const vulnerabilities = parseVulnerabilities(
      response.choices[0].message.content,
      prNumber
    );

    // Filter out false positives
    const filteredVulnerabilities = vulnerabilities.filter(
      (vuln) => !isFalsePositive(vuln, prNumber)
    );

    logger.info("Completed vulnerability analysis:", {
      vulnerabilitiesFound: filteredVulnerabilities.length,
      totalVulnerabilities: vulnerabilities.length,
      falsePositives: vulnerabilities.length - filteredVulnerabilities.length,
      types: filteredVulnerabilities.map((v) => v.type),
    });

    return filteredVulnerabilities;
  } catch (error) {
    logger.error("Error in analyzeCodeDiff:", {
      error: error.message,
      stack: error.stack,
    });

    const isRetryable = await handleAPIError(
      error,
      prNumber,
      "OpenAI API call"
    );
    if (!isRetryable) {
      throw new APIError(
        "Failed to analyze code diff",
        "ANALYSIS_FAILED",
        false
      );
    }
    throw error;
  }
}

/**
 * @function parseVulnerabilities
 * @description Parses AI analysis response into vulnerability objects
 * @param {string} aiResponse - Raw analysis text from AI
 * @param {number} prNumber - Pull request number
 * @returns {Array<Object>} Array of parsed vulnerability objects
 */
function parseVulnerabilities(aiResponse, prNumber) {
  if (!aiResponse) {
    logger.warn("Empty AI response received");
    return [];
  }

  logger.debug("Parsing AI response for vulnerabilities", {
    responseLength: aiResponse.length,
  });

  // Check for explicit "no vulnerabilities" message
  if (
    aiResponse.toLowerCase().includes("no vulnerabilities") ||
    aiResponse.toLowerCase().includes("no security issues")
  ) {
    logger.info("AI explicitly reported no vulnerabilities");
    return [];
  }

  const vulnerabilities = [];

  // Split response into sections for each vulnerability
  const sections = aiResponse.split(
    /(?=Type of vulnerability:|Vulnerability \d+:)/g
  );

  for (const section of sections) {
    try {
      // Skip empty sections or sections without vulnerability info
      if (
        !section.trim() ||
        !section.toLowerCase().includes("type of vulnerability")
      ) {
        continue;
      }

      const vulnerability = {
        prNumber,
        type: extractField(section, "Type of vulnerability"),
        severity: extractField(section, "Severity"),
        confidence: parseFloat(extractField(section, "Confidence score")),
        owaspRef: extractField(section, "OWASP reference"),
        cweRef: extractField(section, "CWE reference"),
        location: extractField(section, "Location in code"),
        description: extractField(section, "Description"),
        suggestedFix: extractField(section, "Suggested fix"),
      };

      // Validate required fields
      if (
        !vulnerability.type ||
        !vulnerability.severity ||
        isNaN(vulnerability.confidence)
      ) {
        logger.warn("Skipping vulnerability due to missing required fields", {
          type: !!vulnerability.type,
          severity: !!vulnerability.severity,
          confidence: !isNaN(vulnerability.confidence),
          section,
        });
        continue;
      }

      // Normalize severity
      vulnerability.severity = vulnerability.severity.toLowerCase();
      if (
        !["critical", "high", "medium", "low"].includes(vulnerability.severity)
      ) {
        logger.warn("Invalid severity level, defaulting to medium", {
          original: vulnerability.severity,
        });
        vulnerability.severity = "medium";
      }

      // Check confidence threshold
      if (vulnerability.confidence < config.getConfidenceThreshold()) {
        logger.debug("Skipping vulnerability due to low confidence", {
          confidence: vulnerability.confidence,
          threshold: config.getConfidenceThreshold(),
        });
        continue;
      }

      vulnerabilities.push(vulnerability);

      logger.debug("Parsed vulnerability:", {
        type: vulnerability.type,
        severity: vulnerability.severity,
        confidence: vulnerability.confidence,
      });
    } catch (error) {
      logger.error("Error parsing vulnerability section:", {
        error: error.message,
        section,
      });
    }
  }

  logger.info("Completed vulnerability parsing", {
    totalSections: sections.length,
    validVulnerabilities: vulnerabilities.length,
  });

  return vulnerabilities;
}

/**
 * @function extractField
 * @description Extracts a field value from analysis text
 * @param {string} text - Text to search
 * @param {string} fieldName - Name of field to extract
 * @returns {string} Extracted field value
 */
function extractField(text, fieldName) {
  if (!text || !fieldName) {
    return null;
  }

  // Try exact match first
  const exactPattern = new RegExp(`${fieldName}:\\s*([^\\n]+)`, "i");
  const exactMatch = text.match(exactPattern);
  if (exactMatch?.[1]) {
    return exactMatch[1].trim();
  }

  // Try flexible match
  const flexPattern = new RegExp(
    `${fieldName}[^\\n]*?[:\\-]\\s*([^\\n]+)`,
    "i"
  );
  const flexMatch = text.match(flexPattern);
  if (flexMatch?.[1]) {
    return flexMatch[1].trim();
  }

  // Try multiline value (for description and suggested fix)
  if (fieldName === "Description" || fieldName === "Suggested fix") {
    const multilinePattern = new RegExp(
      `${fieldName}[^\\n]*?[:\\-]\\s*([\\s\\S]+?)(?=(?:Type of vulnerability|Severity|Confidence score|OWASP reference|CWE reference|Location in code|Description|Suggested fix):|$)`,
      "i"
    );
    const multilineMatch = text.match(multilinePattern);
    if (multilineMatch?.[1]) {
      return multilineMatch[1].trim();
    }
  }

  logger.debug(`Could not extract field: ${fieldName}`, {
    textPreview: text.substring(0, 100) + "...",
  });
  return null;
}

/**
 * @function isFalsePositive
 * @description Checks if a vulnerability type has been marked as false positive
 * @param {Object} vulnerability - Vulnerability to check
 * @param {number} prNumber - Pull request number
 * @returns {boolean} Whether the vulnerability type is marked as false positive
 */
function isFalsePositive(vulnerability, prNumber) {
  // Debug logging to see what we're checking
  logger.debug("Checking if vulnerability is false positive:", {
    vulnerabilityType: vulnerability.type,
    prNumber,
    falsePositiveKeys: Array.from(falsePositives.keys()),
  });

  // Check if this vulnerability type has been marked as false positive
  return Array.from(falsePositives.keys()).some((key) => {
    const typeMatch = key.match(new RegExp(`${prNumber}-([^(]+)`));
    if (!typeMatch) return false;

    const storedType = typeMatch[1].trim();
    const isMatch =
      storedType.toLowerCase() === vulnerability.type.toLowerCase();

    logger.debug("False positive check:", {
      storedType,
      vulnerabilityType: vulnerability.type,
      isMatch,
    });

    return isMatch;
  });
}

/**
 * @async
 * @function handleFalsePositive
 * @description Handles marking a vulnerability type as false positive
 * @param {number} prNumber - Pull request number
 * @param {string} issueId - Vulnerability identifier
 * @param {string} comment - Comment text
 */
async function handleFalsePositive(prNumber, issueId, comment) {
  const fpConfig = config.getFalsePositiveConfig();
  if (!fpConfig.enabled) return;

  // Extract vulnerability type from issueId (e.g., "SQL Injection (server.js:15)" -> "SQL Injection")
  const typeMatch = issueId.match(/^([^(]+)/);
  if (!typeMatch) {
    logger.warn("Could not extract vulnerability type from issueId:", issueId);
    return;
  }
  const vulnerabilityType = typeMatch[1].trim();

  // Store just the vulnerability type as false positive
  const fpKey = `${prNumber}-${vulnerabilityType}`;

  logger.debug("Storing false positive:", {
    prNumber,
    vulnerabilityType,
    fpKey,
    issueId,
  });

  falsePositives.set(fpKey, {
    timestamp: Date.now(),
    comment,
  });

  logger.logFalsePositive(prNumber, vulnerabilityType, comment);
}

/**
 * @async
 * @function postComment
 * @description Posts analysis results as a comment on the PR
 * @param {number} prNumber - Pull request number
 * @param {Array<Object>} vulnerabilities - Detected vulnerabilities
 */
async function postComment(prNumber, vulnerabilities) {
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("Invalid vulnerabilities data");
  }

  let body;
  if (vulnerabilities.length === 0) {
    body = `## Security Review Results

✅ No security vulnerabilities were detected in this pull request.

### Analysis Details
- Analyzed PR: #${prNumber}
- Security Checks Run: ${Object.entries(config.getSecurityChecks())
      .filter(([_, check]) => check.enabled)
      .map(([name, _]) => name)
      .join(", ")}
- Confidence Threshold: ${(config.getConfidenceThreshold() * 100).toFixed(0)}%

If you believe this is incorrect or would like to mark any future findings as false positives, you can comment with:
\`\`\`
@securitybot false-positive "Vulnerability Type" (file.js:line)
\`\`\`
For example:
\`\`\`
@securitybot false-positive SQL Injection (server.js:15)
\`\`\`
Make sure to:
- Use the exact vulnerability type as shown above
- Include the parentheses around the location
- Use the colon between file and line number
- Keep the space between type and location`;
  } else {
    body = generateComment(vulnerabilities);
  }

  await retryWithBackoff(
    async () => {
      await octokit.issues.createComment({
        owner: process.env.GITHUB_REPOSITORY.split("/")[0],
        repo: process.env.GITHUB_REPOSITORY.split("/")[1],
        issue_number: prNumber,
        body,
      });
    },
    config.getMaxRetries(),
    config.getApiTimeout()
  );
}

/**
 * @function generateComment
 * @description Generates a formatted comment with vulnerability findings
 * @param {Array<Object>} vulnerabilities - Detected vulnerabilities
 * @returns {string} Formatted comment text
 */
function generateComment(vulnerabilities) {
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("Invalid vulnerabilities data");
  }

  const severityLevels = config.getSeverityLevels();
  let comment = "## Security Review Results\n\n";

  const groupedVulns = vulnerabilities.reduce((acc, vuln) => {
    if (!vuln.severity) {
      logger.warn("Vulnerability missing severity level", {
        vulnerability: vuln,
      });
      return acc;
    }
    if (!acc[vuln.severity]) {
      acc[vuln.severity] = [];
    }
    acc[vuln.severity].push(vuln);
    return acc;
  }, {});

  const sortedSeverities = Object.entries(severityLevels)
    .filter(([_, level]) => level.enabled)
    .map(([name, _]) => name)
    .filter((severity) => groupedVulns[severity]);

  for (const severity of sortedSeverities) {
    const vulns = groupedVulns[severity];
    if (!vulns || vulns.length === 0) continue;

    const severityConfig = severityLevels[severity];
    if (!severityConfig) {
      logger.warn(`Unknown severity level: ${severity}`);
      continue;
    }

    comment += `### ${
      severity.charAt(0).toUpperCase() + severity.slice(1)
    } Severity Issues\n\n`;

    for (const vuln of vulns) {
      comment += `#### ${vuln.type || "Unknown Vulnerability Type"}\n`;
      comment += `- **Location:** ${vuln.location || "Unknown"}\n`;
      comment += `- **Confidence:** ${
        typeof vuln.confidence === "number"
          ? (vuln.confidence * 100).toFixed(1)
          : "Unknown"
      }%\n`;
      comment += `- **OWASP:** ${vuln.owaspRef || "N/A"}\n`;
      comment += `- **CWE:** ${vuln.cweRef || "N/A"}\n`;
      comment += `- **Description:** ${
        vuln.description || "No description provided"
      }\n`;
      if (vuln.suggestedFix) {
        comment += `- **Suggested Fix:**\n\`\`\`\n${vuln.suggestedFix}\n\`\`\`\n\n`;
      }
    }
  }

  comment += "\n---\n\n";
  comment += "To mark a vulnerability as false positive, comment with:\n";
  comment +=
    '```\n@securitybot false-positive "Vulnerability Type" (file.js:line)\n```\n';
  comment += "For example:\n";
  comment +=
    "```\n@securitybot false-positive SQL Injection (server.js:15)\n```\n";
  comment += "Make sure to:\n";
  comment += "- Use the exact vulnerability type as shown above\n";
  comment += "- Include the parentheses around the location\n";
  comment += "- Use the colon between file and line number\n";
  comment += "- Keep the space between type and location\n";

  return comment;
}

/**
 * @async
 * @function processPullRequest
 * @description Main function to process a pull request
 * @param {number} prNumber - Pull request number
 */
async function processPullRequest(prNumber) {
  try {
    logger.logScanStart(prNumber);

    logger.info("Starting to load false positives...");
    await loadFalsePositives(prNumber);
    logger.info("Finished loading false positives");

    // Get the PR details first
    const { data: pr } = await retryWithBackoff(
      async () => {
        return await octokit.pulls.get({
          owner: process.env.GITHUB_REPOSITORY.split("/")[0],
          repo: process.env.GITHUB_REPOSITORY.split("/")[1],
          pull_number: prNumber,
        });
      },
      config.getMaxRetries(),
      config.getApiTimeout()
    );

    if (!pr) {
      throw new Error("Failed to fetch PR data");
    }

    logger.debug("Fetched PR data:", {
      title: pr.title,
      state: pr.state,
      commits: pr.commits,
      changed_files: pr.changed_files,
    });

    // Get the PR diff using the diff URL directly
    const diffResponse = await retryWithBackoff(
      async () => {
        return await fetch(pr.diff_url, {
          headers: {
            Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github.v3.diff",
          },
        });
      },
      config.getMaxRetries(),
      config.getApiTimeout()
    );

    if (!diffResponse.ok) {
      throw new Error(`Failed to fetch PR diff: ${diffResponse.statusText}`);
    }

    const diff = await diffResponse.text();

    if (!diff) {
      throw new Error("Empty diff received");
    }

    logger.debug("Fetched PR diff:", {
      diffLength: diff.length,
      diffPreview: diff.substring(0, 200) + "...",
    });

    const vulnerabilities = await analyzeCodeDiff(diff, prNumber);

    if (!Array.isArray(vulnerabilities)) {
      throw new Error("Invalid vulnerabilities data returned from analysis");
    }

    logger.debug("Analysis results:", {
      vulnerabilitiesFound: vulnerabilities.length,
      vulnerabilities: vulnerabilities.map((v) => ({
        type: v.type,
        severity: v.severity,
        confidence: v.confidence,
        location: v.location,
      })),
    });

    if (vulnerabilities.length === 0) {
      logger.info("No vulnerabilities found in the analysis");
    }

    await retryWithBackoff(
      async () => {
        await postComment(prNumber, vulnerabilities);
      },
      config.getMaxRetries(),
      config.getApiTimeout()
    );

    logger.info("Processing new comments for false positives...");
    await processNewComments(prNumber);
    logger.info("Finished processing new comments");

    logger.logScanComplete(prNumber, vulnerabilities.length);
  } catch (error) {
    logger.error("Error in processPullRequest:", {
      error: error.message,
      stack: error.stack,
      prNumber,
    });
    if (error instanceof APIError) {
      throw error;
    }
    await handleAPIError(error, prNumber, "PR processing");
    throw error;
  }
}

/**
 * @async
 * @function main
 * @description Entry point for the application
 */
async function main() {
  try {
    const prNumber = process.env.PR_NUMBER;
    if (!prNumber) {
      throw new Error("PR number not provided in environment");
    }

    await processPullRequest(prNumber);
  } catch (error) {
    logger.error("Error in main:", error);
    process.exit(1);
  }
}

module.exports = {
  processPullRequest,
};

// Only run main() if this file is run directly
if (require.main === module) {
  main();
}
