# GitHub Security Review Bot

A GitHub Action that automatically reviews pull requests for security vulnerabilities using AI. The bot analyzes code changes and provides detailed security feedback with OWASP and CWE references.

## Features

- 🔍 **Automated Security Review**

  - Reviews pull requests automatically
  - Analyzes code changes for security vulnerabilities
  - Provides detailed feedback with OWASP and CWE references
  - Configurable security checks and thresholds

- 🤖 **AI-Powered Analysis**

  - Uses GPT-4 for intelligent code analysis
  - Detects complex security vulnerabilities
  - Provides context-aware suggestions
  - Configurable confidence thresholds

- 📊 **Configurable Security Checks**

  - SQL Injection detection
  - Cross-Site Scripting (XSS)
  - Hardcoded secrets
  - Weak cryptography
  - Command injection
  - Path traversal
  - Insecure deserialization
  - Authentication bypass

- 🎯 **False Positive Handling**

  - Mark vulnerabilities as false positives via comments
  - Maintains history of false positives
  - Requires maintainer approval
  - Configurable expiration period

- 📝 **Detailed Reporting**
  - Severity levels (critical, high, medium, low)
  - Confidence scores
  - OWASP and CWE references
  - Suggested fixes
  - Location in code

## Project Setup Guide

1. **Create Project Structure**
   First, create the following directory structure in your project:

   ```
   your-project/              # Your existing project root
   ├── .github/
   │   └── workflows/        # GitHub Actions workflows
   └── security-bot/         # Bot code and configuration
       ├── config/           # Bot configuration
       └── src/             # Source code
   ```

   ```bash
   # Create directories
   mkdir -p .github/workflows
   mkdir -p security-bot/config
   mkdir -p security-bot/src
   ```

2. **Set Up GitHub Actions Workflow**
   Create `.github/workflows/security-bot.yml` with the following content:

   ```yaml
   name: Security Review Bot

   on:
     pull_request:
       types: [opened, synchronize, reopened]
     issue_comment:
       types: [created]

   jobs:
     security-review:
       name: Security Review
       runs-on: ubuntu-latest
       permissions:
         contents: read
         pull-requests: write
         issues: write

       env:
         GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
         OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
         NODE_VERSION: "18"

       steps:
         - name: Checkout repository
           uses: actions/checkout@v4
           with:
             fetch-depth: 0
             token: ${{ secrets.GITHUB_TOKEN }}

         - name: Setup Node.js
           uses: actions/setup-node@v4
           with:
             node-version: ${{ env.NODE_VERSION }}
             cache: "npm"
             cache-dependency-path: security-bot/package-lock.json

         - name: Install dependencies
           working-directory: security-bot
           run: npm ci

         - name: Run security review
           id: security-review
           working-directory: security-bot
           run: node src/index.js
           env:
             GITHUB_REPOSITORY: ${{ github.repository }}
             GITHUB_EVENT_PATH: ${{ github.event_path }}
             GITHUB_EVENT_NAME: ${{ github.event_name }}
             GITHUB_ACTIONS: true
             PR_NUMBER: ${{ github.event.pull_request.number }}
             CONFIG_PATH: config/securitybot-config.yml
           continue-on-error: true

         - name: Upload logs
           if: always()
           uses: actions/upload-artifact@v4
           with:
             name: security-review-logs
             path: security-bot/*.log
             retention-days: 7
   ```

3. **Set Up Bot Configuration**
   Create `security-bot/config/securitybot-config.yml`:

   ```yaml
   # AI Model Configuration
   ai_model:
     provider: "openai"
     model: "gpt-4"
     temperature: 0.3
     max_tokens: 2000

   # Security Checks Configuration
   security_checks:
     sql_injection:
       enabled: true
       severity: critical
       description: "Detects potential SQL injection vulnerabilities"
       owasp: "A03:2021"
       cwe: "CWE-89"
       confidence_threshold: 0.8

   # Severity Levels
   severity_levels:
     critical:
       enabled: true
       threshold: 0.9
       color: "#ff0000"
       description: "Critical security issues that must be addressed immediately"

   # Performance Settings
   max_lines: 1000
   max_retries: 3
   api_timeout: 30000

   # Logging Configuration
   logging:
     level: debug
     file: security-bot.log
     max_size: 10485760 # 10MB
     max_files: 5
   ```

4. **Set Up Source Files**
   Create the following files in the `security-bot/src` directory:

   `security-bot/src/index.js` - Main bot implementation
   `security-bot/src/config.js` - Configuration loader
   `security-bot/src/logger.js` - Logging utility

   You can find the source code for these files in our [GitHub repository](https://github.com/yourusername/github-security-review-bot).

5. **Set Up Package Dependencies**
   Create `security-bot/package.json`:

   ```json
   {
     "name": "github-security-review-bot",
     "version": "1.0.0",
     "dependencies": {
       "@octokit/rest": "^20.0.0",
       "openai": "^4.0.0",
       "js-yaml": "^4.1.0",
       "winston": "^3.11.0",
       "dotenv": "^16.3.1"
     }
   }
   ```

6. **Set Up Environment Variables**
   Create `security-bot/.env`:

   ```env
   OPENAI_API_KEY=your_api_key_here
   ```

   Note: Don't commit this file. Add it to your `.gitignore`.

7. **Configure GitHub Repository**

   - Go to your repository's Settings → Secrets and Variables → Actions
   - Add `OPENAI_API_KEY` with your OpenAI API key

8. **Install Dependencies**
   ```bash
   cd security-bot
   npm install
   ```

## Final Project Structure

After setup, your project structure should look like this:

```
your-project/
├── .github/
│   └── workflows/
│       └── security-bot.yml    # GitHub Actions workflow
├── security-bot/              # Bot directory
│   ├── config/
│   │   └── securitybot-config.yml
│   ├── src/
│   │   ├── index.js          # Main bot implementation
│   │   ├── config.js         # Configuration loader
│   │   └── logger.js         # Logging utility
│   ├── .env                  # Environment variables (not committed)
│   └── package.json         # Dependencies
└── ... (your other project files)
```

## Usage

// ... rest of the existing content ...
