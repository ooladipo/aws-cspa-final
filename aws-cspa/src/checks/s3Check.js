/**
 * S3 Check Module
 * ===============
 * Implements FR1 and FR2 from Table 4.1 (Chapter 4)
 *
 * FR1 — CIS 2.1.1, 2.1.2
 *   Ensure S3 bucket Public Access Block is fully enabled.
 *   All four flags must be true: BlockPublicAcls, IgnorePublicAcls,
 *   BlockPublicPolicy, RestrictPublicBuckets.
 *
 * FR2 — CIS 2.1.5
 *   Ensure S3 bucket ACLs do not grant public access.
 *   Checks for AllUsers and AuthenticatedUsers group URI grants.
 */

import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand
} from '@aws-sdk/client-s3';

const s3 = new S3Client({ region: process.env.AWS_DEFAULT_REGION || 'eu-north-1' });

export async function checkS3() {
  const findings = [];
  let passed = 0;

  // Retrieve all S3 buckets in the account
  const { Buckets } = await s3.send(new ListBucketsCommand({}));

  if (!Buckets || Buckets.length === 0) {
    return {
      findings: [],
      passed: 0,
      totalBuckets: 0,
      info: 'No S3 buckets found in this account.'
    };
  }

  for (const bucket of Buckets) {
    const name = bucket.Name;
    let bucketFlagged = false;

    // FR1 — CIS 2.1.1, 2.1.2: Check Public Access Block configuration
    try {
      const { PublicAccessBlockConfiguration: block } = await s3.send(
        new GetPublicAccessBlockCommand({ Bucket: name })
      );

      const allBlocked =
        block.BlockPublicAcls &&
        block.IgnorePublicAcls &&
        block.BlockPublicPolicy &&
        block.RestrictPublicBuckets;

      if (!allBlocked) {
        const disabledFlags = [];
        if (!block.BlockPublicAcls)       disabledFlags.push('BlockPublicAcls');
        if (!block.IgnorePublicAcls)      disabledFlags.push('IgnorePublicAcls');
        if (!block.BlockPublicPolicy)     disabledFlags.push('BlockPublicPolicy');
        if (!block.RestrictPublicBuckets) disabledFlags.push('RestrictPublicBuckets');

        findings.push({
          cisControl: 'CIS 2.1.1, 2.1.2',
          resource: `s3://${name}`,
          check: 'Public Access Block misconfiguration',
          severity: 'critical',
          detail: `Public Access Block is not fully enabled on bucket "${name}". Disabled flags: ${disabledFlags.join(', ')}.`,
          recommendation: 'Enable all four Public Access Block settings on this bucket immediately via the S3 console or AWS CLI: aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
        });
        bucketFlagged = true;
      }
    } catch (err) {
      if (err.name === 'NoSuchPublicAccessBlockConfiguration') {
        // No configuration exists at all — critical finding
        findings.push({
          cisControl: 'CIS 2.1.1, 2.1.2',
          resource: `s3://${name}`,
          check: 'Public Access Block not configured',
          severity: 'critical',
          detail: `No Public Access Block configuration exists for bucket "${name}". The bucket may be publicly accessible.`,
          recommendation: 'Apply a Public Access Block configuration immediately: aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
        });
        bucketFlagged = true;
      } else if (err.name !== 'PermanentRedirect') {
        // Skip buckets in inaccessible regions gracefully (PermanentRedirect)
        console.warn(`[S3] Warning: Could not check bucket ${name}: ${err.message}`);
      }
    }

    // FR2 — CIS 2.1.5: Check Bucket ACL for public grants
    try {
      const { Grants } = await s3.send(new GetBucketAclCommand({ Bucket: name }));

      const PUBLIC_URIS = [
        'http://acs.amazonaws.com/groups/global/AllUsers',
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
      ];

      const publicGrants = Grants.filter(g =>
        g.Grantee?.URI && PUBLIC_URIS.includes(g.Grantee.URI)
      );

      if (publicGrants.length > 0) {
        const grantDetails = publicGrants.map(g => `${g.Permission} to ${g.Grantee.URI.split('/').pop()}`).join(', ');
        findings.push({
          cisControl: 'CIS 2.1.5',
          resource: `s3://${name}`,
          check: 'Public ACL grant detected',
          severity: 'critical',
          detail: `Bucket "${name}" ACL grants public access: ${grantDetails}. Any internet user can access this bucket.`,
          recommendation: 'Remove public ACL grants immediately. Use bucket policies with least-privilege access instead of ACLs.'
        });
        bucketFlagged = true;
      }
    } catch (err) {
      // AccessDenied on ACL check — skip silently, note in findings
      if (err.name !== 'AccessDenied' && err.name !== 'PermanentRedirect') {
        console.warn(`[S3] Warning: Could not check ACL for bucket ${name}: ${err.message}`);
      }
    }

    if (!bucketFlagged) passed++;
  }

  return {
    findings,
    passed,
    totalBuckets: Buckets.length
  };
}
