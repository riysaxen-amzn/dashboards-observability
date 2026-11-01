/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Classifies AWS CloudWatch datasource failures — credential-chain misses,
 * invalid/expired STS tokens, IAM denials, throttling, and unreachable
 * regional endpoints — so a CloudWatch outage surfaces as a named failure
 * class with remediation instead of a raw SDK message.
 *
 * Matching is deliberately two-pronged:
 *   - AWS SDK error names (`UnrecognizedClientException`, `ExpiredTokenException`,
 *     …) are globally unambiguous, so they match regardless of `sourceType`.
 *   - Transport-level shapes (DNS failure on a mistyped region endpoint,
 *     connection refused) are only claimed when the boundary tagged the
 *     context with `sourceType: 'cloudwatch'` — the same shapes from an
 *     OpenSearch or Prometheus fetch belong to other classifiers.
 *
 * Wording is inlined (not added to the shared catalog) per the extension
 * model: the catalog stays provider-neutral, and provider-specific phrasing
 * rides on the classifier itself.
 */

import type {
  ClassifierResult,
  ErrorClassifier,
  MessageDescriptor,
  RawErrorContext,
} from '../types';
import { rawDetails } from './util';

const ID_PREFIX = 'observability.error.cloudwatch';

/** Stable machine codes for CloudWatch failure classes. */
export const CloudWatchErrorCode = {
  CREDENTIALS_MISSING: 'CLOUDWATCH_CREDENTIALS_MISSING',
  SIGN_IN_UNSUPPORTED: 'CLOUDWATCH_SIGN_IN_UNSUPPORTED',
  AUTH_INVALID: 'CLOUDWATCH_AUTH_INVALID',
  AUTH_EXPIRED: 'CLOUDWATCH_AUTH_EXPIRED',
  ACCESS_DENIED: 'CLOUDWATCH_ACCESS_DENIED',
  THROTTLED: 'CLOUDWATCH_THROTTLED',
  ENDPOINT_UNREACHABLE: 'CLOUDWATCH_ENDPOINT_UNREACHABLE',
  INVALID_REQUEST: 'CLOUDWATCH_INVALID_REQUEST',
  QUOTA_EXCEEDED: 'CLOUDWATCH_QUOTA_EXCEEDED',
  ALARM_NOT_FOUND: 'CLOUDWATCH_ALARM_NOT_FOUND',
} as const;

/**
 * Operation-id prefix of the routes that change alarms (`cloudwatch.alarm.write.create`, …).
 * Their access-denied remediation names the write permissions.
 */
export const CLOUDWATCH_WRITE_OPERATION_PREFIX = 'cloudwatch.alarm.write.';

function msg(code: string, key: string, defaultMessage: string): MessageDescriptor {
  return { id: `${ID_PREFIX}.${code}.${key}`, defaultMessage };
}

function messages(
  code: string,
  title: string,
  message: string,
  remediation: string
): ClassifierResult['messages'] {
  return {
    title: msg(code, 'title', title),
    message: msg(code, 'message', message),
    remediation: msg(code, 'remediation', remediation),
  };
}

// --- error-name sets (AWS SDK v3 `Error.name` values) ----------------------

/**
 * The sign-in method carries no AWS credentials at all, so signing in again can't help. Mirrors
 * `CLOUDWATCH_SIGN_IN_UNSUPPORTED_ERROR_NAME` in the CloudWatch source contract.
 */
const SIGN_IN_UNSUPPORTED_NAMES = new Set(['CloudWatchSignInUnsupported']);

/** Credential chain produced nothing (or our typed wrapper for it). */
const CREDENTIALS_MISSING_NAMES = new Set([
  'CredentialsProviderError',
  'CloudWatchCredentialsError',
]);

/** Credentials present but rejected as malformed / unknown / bad signature. */
const AUTH_INVALID_NAMES = new Set([
  'UnrecognizedClientException',
  'InvalidClientTokenId',
  'SignatureDoesNotMatch',
  'IncompleteSignature',
]);

/** Credentials were valid once, but the session/token has expired. */
const AUTH_EXPIRED_NAMES = new Set([
  'ExpiredToken',
  'ExpiredTokenException',
  'RequestExpired',
  'TokenRefreshRequired',
]);

/**
 * Authenticated but not authorized for the API (IAM policy). Exported so callers can tell a
 * denied call from other failures by name, not by message text.
 */
export const CLOUDWATCH_ACCESS_DENIED_ERROR_NAMES: ReadonlySet<string> = new Set([
  'AccessDenied',
  'AccessDeniedException',
  'AuthorizationErrorException',
  'UnauthorizedOperation',
]);

/** API rate limiting. */
const THROTTLED_NAMES = new Set([
  'Throttling',
  'ThrottlingException',
  'TooManyRequestsException',
  'RequestLimitExceeded',
  'LimitExceededException',
]);

/**
 * The account's alarm quota is used up (`PutMetricAlarm`'s `LimitExceeded` fault). Not a
 * throttle: retrying won't help until alarms are deleted or the quota is raised.
 */
const QUOTA_EXCEEDED_NAMES = new Set(['LimitExceededFault', 'LimitExceeded']);

/** CloudWatch rejected the request's parameters (as opposed to our own validation). */
const INVALID_REQUEST_NAMES = new Set([
  'InvalidParameterValue',
  'InvalidParameterValueException',
  'InvalidParameterCombination',
  'InvalidParameterCombinationException',
  'MissingParameter',
  'MissingRequiredParameterException',
  'InvalidFormatFault',
]);

/** The named alarm doesn't exist (e.g. deleted elsewhere since the list was read). */
const ALARM_NOT_FOUND_NAMES = new Set(['ResourceNotFound', 'ResourceNotFoundException']);

function isWriteOperation(ctx: RawErrorContext): boolean {
  return (
    typeof ctx.operation === 'string' && ctx.operation.startsWith(CLOUDWATCH_WRITE_OPERATION_PREFIX)
  );
}

/**
 * Transport failures. A mistyped/nonexistent region manifests as a DNS
 * failure on `monitoring.<region>.amazonaws.com`, so ENOTFOUND is the
 * canonical "bad region" signal. Claimed only for `sourceType: 'cloudwatch'`.
 */
const TRANSPORT_ERROR_NAMES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET']);
const TRANSPORT_MESSAGE_RE = /getaddrinfo|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET/;

function isCloudWatchSource(ctx: RawErrorContext): boolean {
  return ctx.sourceType === 'cloudwatch';
}

function isTransportFailure(ctx: RawErrorContext): boolean {
  if (ctx.errorName && TRANSPORT_ERROR_NAMES.has(ctx.errorName)) return true;
  return typeof ctx.message === 'string' && TRANSPORT_MESSAGE_RE.test(ctx.message);
}

function isCredentialsMissing(ctx: RawErrorContext): boolean {
  if (ctx.errorName && CREDENTIALS_MISSING_NAMES.has(ctx.errorName)) return true;
  return (
    isCloudWatchSource(ctx) &&
    typeof ctx.message === 'string' &&
    /could not load credentials/i.test(ctx.message)
  );
}

export const cloudWatchClassifier: ErrorClassifier = {
  name: 'core.cloudwatch',
  priority: 90,
  match: (ctx: RawErrorContext): boolean => {
    if (ctx.errorName) {
      if (
        SIGN_IN_UNSUPPORTED_NAMES.has(ctx.errorName) ||
        CREDENTIALS_MISSING_NAMES.has(ctx.errorName) ||
        AUTH_INVALID_NAMES.has(ctx.errorName) ||
        AUTH_EXPIRED_NAMES.has(ctx.errorName) ||
        CLOUDWATCH_ACCESS_DENIED_ERROR_NAMES.has(ctx.errorName) ||
        THROTTLED_NAMES.has(ctx.errorName)
      ) {
        return true;
      }
      // Generic-sounding AWS names (parameter, quota and not-found faults) are only claimed for
      // CloudWatch, so another provider's error of the same name isn't relabeled.
      if (
        isCloudWatchSource(ctx) &&
        (QUOTA_EXCEEDED_NAMES.has(ctx.errorName) ||
          INVALID_REQUEST_NAMES.has(ctx.errorName) ||
          ALARM_NOT_FOUND_NAMES.has(ctx.errorName))
      ) {
        return true;
      }
    }
    if (isCredentialsMissing(ctx)) return true;
    // Transport shapes are ambiguous across providers — only claim them when
    // the boundary tagged this failure as CloudWatch-sourced.
    return isCloudWatchSource(ctx) && isTransportFailure(ctx);
  },
  classify: (ctx: RawErrorContext): ClassifierResult => {
    const details = rawDetails(ctx.message);
    const name = ctx.errorName || '';

    if (SIGN_IN_UNSUPPORTED_NAMES.has(name)) {
      return {
        category: 'PERMISSION_DENIED',
        code: CloudWatchErrorCode.SIGN_IN_UNSUPPORTED,
        retryable: false,
        httpStatus: 403,
        details,
        messages: messages(
          CloudWatchErrorCode.SIGN_IN_UNSUPPORTED,
          "CloudWatch isn't available for this sign-in",
          "This sign-in method doesn't provide AWS credentials, so CloudWatch alarms can't be read.",
          'Sign in with an identity that has AWS credentials to see CloudWatch alarms, or ask an administrator which sign-in methods support them.'
        ),
      };
    }
    if (isCredentialsMissing(ctx)) {
      return {
        category: 'PERMISSION_DENIED',
        code: CloudWatchErrorCode.CREDENTIALS_MISSING,
        retryable: false,
        httpStatus: 403,
        details,
        messages: messages(
          CloudWatchErrorCode.CREDENTIALS_MISSING,
          'CloudWatch credentials missing',
          'No AWS credentials were available for this request, so CloudWatch could not be queried.',
          'Sign in again, then retry. If it keeps happening, ask an administrator to check CloudWatch access for this deployment.'
        ),
      };
    }
    if (AUTH_EXPIRED_NAMES.has(name)) {
      return {
        category: 'PERMISSION_DENIED',
        code: CloudWatchErrorCode.AUTH_EXPIRED,
        retryable: false,
        httpStatus: 403,
        details,
        messages: messages(
          CloudWatchErrorCode.AUTH_EXPIRED,
          'AWS session expired',
          'The AWS credentials have expired, so CloudWatch rejected the request.',
          'Sign in again to get a new session, then retry.'
        ),
      };
    }
    if (AUTH_INVALID_NAMES.has(name)) {
      return {
        category: 'PERMISSION_DENIED',
        code: CloudWatchErrorCode.AUTH_INVALID,
        retryable: false,
        httpStatus: 403,
        details,
        messages: messages(
          CloudWatchErrorCode.AUTH_INVALID,
          'AWS credentials rejected',
          'CloudWatch did not recognize the AWS credentials for this request.',
          'Sign in again, then retry. If it keeps happening, ask an administrator to check CloudWatch access for this deployment.'
        ),
      };
    }
    if (CLOUDWATCH_ACCESS_DENIED_ERROR_NAMES.has(name)) {
      return {
        category: 'PERMISSION_DENIED',
        code: CloudWatchErrorCode.ACCESS_DENIED,
        retryable: false,
        httpStatus: 403,
        details,
        messages: isWriteOperation(ctx)
          ? {
              title: msg(
                CloudWatchErrorCode.ACCESS_DENIED,
                'writeTitle',
                'CloudWatch change denied'
              ),
              message: msg(
                CloudWatchErrorCode.ACCESS_DENIED,
                'writeMessage',
                "Your AWS identity isn't allowed to make this change to CloudWatch alarms."
              ),
              remediation: msg(
                CloudWatchErrorCode.ACCESS_DENIED,
                'writeRemediation',
                'Ask an administrator to grant your identity cloudwatch:PutMetricAlarm, cloudwatch:DeleteAlarms, cloudwatch:EnableAlarmActions and cloudwatch:DisableAlarmActions (and cloudwatch:TagResource to tag new alarms), then retry.'
              ),
            }
          : messages(
              CloudWatchErrorCode.ACCESS_DENIED,
              'CloudWatch access denied',
              'The AWS credentials are valid but not authorized for the CloudWatch API that was called.',
              'Ask an administrator to grant your identity cloudwatch:DescribeAlarms, cloudwatch:DescribeAlarmHistory and cloudwatch:GetMetricData, then retry.'
            ),
      };
    }
    if (QUOTA_EXCEEDED_NAMES.has(name)) {
      return {
        category: 'PRECONDITION_FAILED',
        code: CloudWatchErrorCode.QUOTA_EXCEEDED,
        retryable: false,
        httpStatus: 400,
        details,
        messages: messages(
          CloudWatchErrorCode.QUOTA_EXCEEDED,
          'CloudWatch alarm quota reached',
          'This account has reached its CloudWatch alarm quota in this Region, so the alarm was not created.',
          'Delete alarms you no longer need, or ask an administrator to request a higher CloudWatch alarm quota, then retry.'
        ),
      };
    }
    if (INVALID_REQUEST_NAMES.has(name)) {
      return {
        category: 'VALIDATION',
        code: CloudWatchErrorCode.INVALID_REQUEST,
        retryable: false,
        httpStatus: 400,
        details,
        messages: messages(
          CloudWatchErrorCode.INVALID_REQUEST,
          'CloudWatch rejected the alarm settings',
          "CloudWatch didn't accept one of the alarm's settings, for example a metric, statistic, unit or period combination it doesn't support.",
          'Check the metric, statistic, unit and period, then try again.'
        ),
      };
    }
    if (ALARM_NOT_FOUND_NAMES.has(name)) {
      return {
        category: 'NOT_FOUND',
        code: CloudWatchErrorCode.ALARM_NOT_FOUND,
        retryable: false,
        httpStatus: 404,
        details,
        messages: messages(
          CloudWatchErrorCode.ALARM_NOT_FOUND,
          'CloudWatch alarm not found',
          'The alarm no longer exists. It may have been deleted or renamed outside this view.',
          'Refresh the list and try again.'
        ),
      };
    }
    if (THROTTLED_NAMES.has(name)) {
      return {
        category: 'RATE_LIMITED',
        code: CloudWatchErrorCode.THROTTLED,
        retryable: true,
        httpStatus: 429,
        details,
        messages: messages(
          CloudWatchErrorCode.THROTTLED,
          'CloudWatch is throttling requests',
          'The CloudWatch API rate limit was hit, so the request was rejected.',
          'Wait a moment and retry.'
        ),
      };
    }
    // Remaining match: transport failure on a CloudWatch fetch.
    return {
      category: 'UPSTREAM_UNAVAILABLE',
      code: CloudWatchErrorCode.ENDPOINT_UNREACHABLE,
      retryable: true,
      httpStatus: 502,
      details,
      messages: messages(
        CloudWatchErrorCode.ENDPOINT_UNREACHABLE,
        'CloudWatch endpoint unreachable',
        'The CloudWatch regional endpoint could not be reached. The configured region may be invalid, or there may be a network problem.',
        'Retry in a moment. If it keeps happening, ask an administrator to check the CloudWatch region and network access for this deployment.'
      ),
    };
  },
};
