/**
 * CloudTrail Check Module
 * =======================
 * Implements FR5, FR6, FR7, and FR8 from Table 4.1 (Chapter 4)
 *
 * FR5 — CIS 3.3 : CloudTrail trail not actively logging
 * FR6 — CIS 3.1 : CloudTrail trail not configured for multi-region
 * FR7 — CIS 3.2 : CloudTrail log file validation not enabled
 * FR8 — CIS 3.3 : No CloudTrail trails configured in the account
 *
 * Note: includeShadowTrails is set to false to prevent duplicate findings
 * from shadow trails (read-only replicas of multi-region trails).
 * See Section 4.6.4 of dissertation for full explanation.
 */

import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand
} from '@aws-sdk/client-cloudtrail';

const ct = new CloudTrailClient({ region: process.env.AWS_DEFAULT_REGION || 'eu-north-1' });

export async function checkCloudTrail() {
  const findings = [];
  let passed = 0;

  // Retrieve home region trails only (excludes shadow trails — see 4.6.4)
  const { trailList } = await ct.send(
    new DescribeTrailsCommand({ includeShadowTrails: false })
  );

  // FR8 — CIS 3.3 (derived): No trails configured at all
  if (!trailList || trailList.length === 0) {
    findings.push({
      cisControl: 'CIS 3.3',
      resource: 'cloudtrail::account',
      check: 'No CloudTrail trails configured',
      severity: 'critical',
      detail: 'No CloudTrail trails are configured in this account. All API activity is unlogged and the account has no audit trail for security investigations or compliance.',
      recommendation: 'Create at least one multi-region CloudTrail trail immediately: aws cloudtrail create-trail --name management-trail --s3-bucket-name <your-log-bucket> --is-multi-region-trail --enable-log-file-validation'
    });
    return { findings, passed, totalTrails: 0 };
  }

  for (const trail of trailList) {
    const trailName = trail.Name;
    const trailArn = trail.TrailARN;
    let trailFlagged = false;

    // FR5 — CIS 3.3: Check whether the trail is actively logging
    try {
      const status = await ct.send(
        new GetTrailStatusCommand({ Name: trailArn })
      );

      if (!status.IsLogging) {
        findings.push({
          cisControl: 'CIS 3.3',
          resource: trailArn,
          check: 'CloudTrail logging disabled',
          severity: 'critical',
          detail: `Trail "${trailName}" exists but logging is currently DISABLED. No API events are being recorded. Last started: ${status.LatestDeliveryTime || 'unknown'}.`,
          recommendation: `Enable logging immediately: aws cloudtrail start-logging --name ${trailName}`
        });
        trailFlagged = true;
      } else {
        passed++;
      }
    } catch (err) {
      findings.push({
        cisControl: 'CIS 3.3',
        resource: trailArn,
        check: 'CloudTrail status unreadable',
        severity: 'medium',
        detail: `Could not retrieve logging status for trail "${trailName}": ${err.message}`,
        recommendation: 'Verify IAM permissions include cloudtrail:GetTrailStatus and review trail configuration.'
      });
      trailFlagged = true;
    }

    // FR6 — CIS 3.1: Check whether the trail covers all regions
    if (!trail.IsMultiRegionTrail) {
      findings.push({
        cisControl: 'CIS 3.1',
        resource: trailArn,
        check: 'CloudTrail single-region trail only',
        severity: 'high',
        detail: `Trail "${trailName}" only covers a single region. API activity in other AWS regions is not captured, leaving blind spots for security monitoring.`,
        recommendation: `Convert to a multi-region trail: aws cloudtrail update-trail --name ${trailName} --is-multi-region-trail`
      });
      trailFlagged = true;
    } else {
      passed++;
    }

    // FR7 — CIS 3.2: Check whether log file validation is enabled
    if (!trail.LogFileValidationEnabled) {
      findings.push({
        cisControl: 'CIS 3.2',
        resource: trailArn,
        check: 'CloudTrail log file validation disabled',
        severity: 'medium',
        detail: `Trail "${trailName}" does not have log file validation enabled. Without SHA-256 hash validation, log files could be tampered with or deleted without detection.`,
        recommendation: `Enable log file validation: aws cloudtrail update-trail --name ${trailName} --enable-log-file-validation`
      });
      trailFlagged = true;
    } else {
      passed++;
    }

    if (!trailFlagged) passed++;
  }

  return {
    findings,
    passed,
    totalTrails: trailList.length
  };
}
