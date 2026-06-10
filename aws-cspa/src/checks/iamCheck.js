/**
 * IAM Check Module
 * ================
 * Implements FR3 and FR4 from Table 4.1 (Chapter 4)
 *
 * FR3 — CIS 1.1
 *   Avoid the use of wildcard IAM policies.
 *   Detects customer-managed policies with Action:* and/or Resource:*
 *   in Allow statements.
 *   Severity mapping:
 *     Action:* AND Resource:* = critical (full admin equivalent)
 *     Action:* only           = high
 *     Resource:* only         = medium
 *
 * FR4 — CIS 1.16
 *   Ensure IAM policies are attached only to groups or roles, not users.
 *   Detects managed and inline policies attached directly to IAM users.
 */

import {
  IAMClient,
  ListPoliciesCommand,
  GetPolicyVersionCommand,
  ListUsersCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand
} from '@aws-sdk/client-iam';

const iam = new IAMClient({});

/**
 * Evaluates a single policy statement for wildcard actions or resources.
 * Returns flags indicating which wildcards were found.
 */
function evaluateStatement(statement) {
  if (statement.Effect !== 'Allow') return { wildcardAction: false, wildcardResource: false };

  const actions = Array.isArray(statement.Action)
    ? statement.Action
    : [statement.Action || ''];

  const resources = Array.isArray(statement.Resource)
    ? statement.Resource
    : [statement.Resource || ''];

  return {
    wildcardAction: actions.some(a => a === '*'),
    wildcardResource: resources.some(r => r === '*')
  };
}

export async function checkIAM() {
  const findings = [];
  let passed = 0;

  // FR3 — CIS 1.1: Check customer-managed IAM policies for wildcards
  let marker;
  do {
    const response = await iam.send(
      new ListPoliciesCommand({ Scope: 'Local', Marker: marker })
    );

    const { Policies, Marker, IsTruncated } = response;
    marker = IsTruncated ? Marker : undefined;

    for (const policy of Policies) {
      try {
        const { PolicyVersion } = await iam.send(
          new GetPolicyVersionCommand({
            PolicyArn: policy.Arn,
            VersionId: policy.DefaultVersionId
          })
        );

        // IAM policy documents are URL-encoded — decode before parsing
        const document = JSON.parse(decodeURIComponent(PolicyVersion.Document));
        const statements = Array.isArray(document.Statement)
          ? document.Statement
          : [document.Statement];

        let policyFlagged = false;

        for (const stmt of statements) {
          const { wildcardAction, wildcardResource } = evaluateStatement(stmt);

          if (wildcardAction && wildcardResource) {
            // CIS 1.1: Full admin wildcard — critical severity
            findings.push({
              cisControl: 'CIS 1.1',
              resource: policy.Arn,
              check: 'Full admin wildcard policy',
              severity: 'critical',
              detail: `Policy "${policy.PolicyName}" grants Action:* on Resource:* — equivalent to full administrator access. This violates the principle of least privilege.`,
              recommendation: 'Replace wildcard permissions with specific IAM actions and resource ARNs. Use AWS IAM Access Analyzer to identify required permissions.'
            });
            policyFlagged = true;
            break;
          } else if (wildcardAction) {
            // Action:* without resource constraint — high severity
            findings.push({
              cisControl: 'CIS 1.1',
              resource: policy.Arn,
              check: 'Wildcard action in IAM policy',
              severity: 'high',
              detail: `Policy "${policy.PolicyName}" uses Action:* which grants unrestricted access to all actions within the applicable service.`,
              recommendation: 'Replace Action:* with the specific IAM actions this policy requires. Refer to the AWS IAM policy reference for service-specific actions.'
            });
            policyFlagged = true;
            break;
          } else if (wildcardResource) {
            // Resource:* without action constraint — medium severity
            findings.push({
              cisControl: 'CIS 1.1',
              resource: policy.Arn,
              check: 'Wildcard resource in IAM policy',
              severity: 'medium',
              detail: `Policy "${policy.PolicyName}" applies permissions to Resource:* across all resources of the applicable type.`,
              recommendation: 'Scope resource ARNs to specific resources this policy needs to access, using resource-level permissions where the service supports them.'
            });
            policyFlagged = true;
            break;
          }
        }

        if (!policyFlagged) passed++;
      } catch (err) {
        // Skip policies we cannot read (e.g. access denied on specific policy versions)
        console.warn(`[IAM] Warning: Could not read policy ${policy.PolicyName}: ${err.message}`);
      }
    }
  } while (marker);

  // FR4 — CIS 1.16: Check for policies attached directly to IAM users
  const { Users } = await iam.send(new ListUsersCommand({}));

  for (const user of Users) {
    try {
      const [{ AttachedPolicies }, { PolicyNames: inlinePolicies }] = await Promise.all([
        iam.send(new ListAttachedUserPoliciesCommand({ UserName: user.UserName })),
        iam.send(new ListUserPoliciesCommand({ UserName: user.UserName }))
      ]);

      const managedCount = AttachedPolicies.length;
      const inlineCount = inlinePolicies.length;

      if (managedCount > 0 || inlineCount > 0) {
        findings.push({
          cisControl: 'CIS 1.16',
          resource: `iam::user/${user.UserName}`,
          check: 'IAM policy attached directly to user',
          severity: 'medium',
          detail: `User "${user.UserName}" has ${managedCount} managed and ${inlineCount} inline polic${managedCount + inlineCount === 1 ? 'y' : 'ies'} attached directly. This makes permission management harder and less auditable.`,
          recommendation: 'Move permissions to an IAM Group or Role and add the user to the appropriate group. Detach all policies directly assigned to individual users.'
        });
      } else {
        passed++;
      }
    } catch (err) {
      console.warn(`[IAM] Warning: Could not check policies for user ${user.UserName}: ${err.message}`);
    }
  }

  return { findings, passed };
}
