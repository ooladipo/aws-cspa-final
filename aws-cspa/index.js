/**
 * AWS Cloud Security Posture Assessment Tool (aws-cspa)
 * ======================================================
 * MSc Cybersecurity Project — Arden University Berlin
 * Author: Oladipupo Okebunmi (24156787)
 *
 * Implements 8 checks mapped to CIS AWS Foundations Benchmark v2.0.0:
 *
 * S3 Checks:
 *   FR1 — CIS 2.1.1, 2.1.2 : S3 Public Access Block misconfiguration
 *   FR2 — CIS 2.1.5         : S3 Bucket ACL public grants
 *
 * IAM Checks:
 *   FR3 — CIS 1.1           : Wildcard Action/Resource in IAM policy
 *   FR4 — CIS 1.16          : IAM policy attached directly to user
 *
 * CloudTrail Checks:
 *   FR5 — CIS 3.3           : CloudTrail trail not actively logging
 *   FR6 — CIS 3.1           : CloudTrail trail not multi-region
 *   FR7 — CIS 3.2           : CloudTrail log file validation disabled
 *   FR8 — CIS 3.3 (derived) : No CloudTrail trails configured at all
 */

import { checkS3 } from './src/checks/s3Check.js';
import { checkIAM } from './src/checks/iamCheck.js';
import { checkCloudTrail } from './src/checks/cloudtrailCheck.js';
import { generateReport } from './src/report/reportGenerator.js';
import chalk from 'chalk';
import ora from 'ora';

const TOOL_NAME = 'AWS Cloud Security Posture Assessment Tool';
const VERSION = '1.0.0';

async function runAssessment() {
  console.log('\n' + chalk.bold.cyan('='.repeat(62)));
  console.log(chalk.bold.cyan(`  ${TOOL_NAME}`));
  console.log(chalk.cyan(`  Version ${VERSION} | MSc Cybersecurity | Arden University Berlin`));
  console.log(chalk.bold.cyan('='.repeat(62)) + '\n');

  const results = {
    timestamp: new Date().toISOString(),
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      passed: 0
    },
    checks: {}
  };

  // FR1, FR2 — S3 Checks (CIS 2.1.1, 2.1.2, 2.1.5)
  const s3Spinner = ora(chalk.yellow('[S3] Checking public access block and ACL configurations...')).start();
  try {
    results.checks.s3 = await checkS3();
    s3Spinner.succeed(chalk.green('[S3] Check complete'));
  } catch (err) {
    s3Spinner.fail(chalk.red(`[S3] Check failed: ${err.message}`));
    results.checks.s3 = { error: err.message, findings: [], passed: 0 };
  }

  // FR3, FR4 — IAM Checks (CIS 1.1, 1.16)
  const iamSpinner = ora(chalk.yellow('[IAM] Checking policy permissions and user attachments...')).start();
  try {
    results.checks.iam = await checkIAM();
    iamSpinner.succeed(chalk.green('[IAM] Check complete'));
  } catch (err) {
    iamSpinner.fail(chalk.red(`[IAM] Check failed: ${err.message}`));
    results.checks.iam = { error: err.message, findings: [], passed: 0 };
  }

  // FR5, FR6, FR7, FR8 — CloudTrail Checks (CIS 3.1, 3.2, 3.3)
  const ctSpinner = ora(chalk.yellow('[CloudTrail] Checking logging status, coverage, and validation...')).start();
  try {
    results.checks.cloudtrail = await checkCloudTrail();
    ctSpinner.succeed(chalk.green('[CloudTrail] Check complete'));
  } catch (err) {
    ctSpinner.fail(chalk.red(`[CloudTrail] Check failed: ${err.message}`));
    results.checks.cloudtrail = { error: err.message, findings: [], passed: 0 };
  }

  // Tally summary counts from all findings
  for (const checkKey of Object.keys(results.checks)) {
    const check = results.checks[checkKey];
    if (check.findings) {
      for (const finding of check.findings) {
        if (results.summary[finding.severity] !== undefined) {
          results.summary[finding.severity]++;
        }
      }
      results.summary.passed += check.passed || 0;
    }
  }

  // Generate HTML report
  console.log('\n' + chalk.yellow('Generating HTML risk report...'));
  const reportPath = await generateReport(results);

  // Print terminal summary
  console.log('\n' + chalk.bold('-'.repeat(62)));
  console.log(chalk.bold('  ASSESSMENT SUMMARY'));
  console.log(chalk.bold('-'.repeat(62)));
  console.log(chalk.red(`  Critical : ${results.summary.critical}`));
  console.log(chalk.yellow(`  High     : ${results.summary.high}`));
  console.log(chalk.yellow(`  Medium   : ${results.summary.medium}`));
  console.log(chalk.blue(`  Low      : ${results.summary.low}`));
  console.log(chalk.green(`  Passed   : ${results.summary.passed}`));
  console.log(chalk.bold('-'.repeat(62)));
  console.log(chalk.cyan(`\n  Report saved to: ${reportPath}\n`));
}

runAssessment().catch(err => {
  console.error(chalk.red('\n[FATAL] Assessment failed:'), err.message);
  process.exit(1);
});
