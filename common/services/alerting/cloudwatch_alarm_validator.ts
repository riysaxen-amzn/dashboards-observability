/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Validation for CloudWatch metric alarms this plugin writes. Shared by the create form (field
 * errors as the user types) and the write routes (the server never trusts the browser), so the
 * two can't drift.
 *
 * Scope on purpose: single-metric, static-threshold alarms whose actions are SNS topics. Other
 * action types (EC2 stop/terminate/reboot, Auto Scaling, Systems Manager, Lambda) can change or
 * destroy resources, so they are refused here rather than relying on the caller's IAM policy.
 */

import type {
  CloudWatchAlarm,
  CloudWatchComparisonOperator,
  CloudWatchMetricAlarmInput,
  CloudWatchStatistic,
  CloudWatchTreatMissingData,
} from '../../types/alerting';
import type { ValidationResult } from './validators';

export const CLOUDWATCH_ALARM_NAME_MAX = 255;
export const CLOUDWATCH_ALARM_DESCRIPTION_MAX = 1024;
export const CLOUDWATCH_NAMESPACE_MAX = 255;
export const CLOUDWATCH_METRIC_NAME_MAX = 255;
export const CLOUDWATCH_DIMENSIONS_MAX = 30;
export const CLOUDWATCH_DIMENSION_NAME_MAX = 255;
export const CLOUDWATCH_DIMENSION_VALUE_MAX = 1024;
/** CloudWatch allows at most 5 actions per state. */
export const CLOUDWATCH_ACTIONS_PER_STATE_MAX = 5;
export const CLOUDWATCH_TAGS_MAX = 50;
export const CLOUDWATCH_TAG_KEY_MAX = 128;
export const CLOUDWATCH_TAG_VALUE_MAX = 256;
/** Periods below a minute are high-resolution and must be one of these. */
export const CLOUDWATCH_HIGH_RESOLUTION_PERIODS: readonly number[] = [10, 20, 30];
export const CLOUDWATCH_PERIOD_MAX_SECONDS = 86400;
/** An alarm's total evaluation window (period × evaluation periods) can't exceed 7 days. */
export const CLOUDWATCH_EVALUATION_WINDOW_MAX_SECONDS = 7 * 86400;

export const CLOUDWATCH_COMPARISON_OPERATORS: readonly CloudWatchComparisonOperator[] = [
  'GreaterThanThreshold',
  'GreaterThanOrEqualToThreshold',
  'LessThanThreshold',
  'LessThanOrEqualToThreshold',
];

export const CLOUDWATCH_STATISTICS: readonly CloudWatchStatistic[] = [
  'Average',
  'Sum',
  'Minimum',
  'Maximum',
  'SampleCount',
];

export const CLOUDWATCH_TREAT_MISSING_DATA: readonly CloudWatchTreatMissingData[] = [
  'missing',
  'notBreaching',
  'breaching',
  'ignore',
];

export const CLOUDWATCH_UNITS: readonly string[] = [
  'Seconds',
  'Microseconds',
  'Milliseconds',
  'Bytes',
  'Kilobytes',
  'Megabytes',
  'Gigabytes',
  'Terabytes',
  'Bits',
  'Kilobits',
  'Megabits',
  'Gigabits',
  'Terabits',
  'Percent',
  'Count',
  'Bytes/Second',
  'Kilobytes/Second',
  'Megabytes/Second',
  'Gigabytes/Second',
  'Terabytes/Second',
  'Bits/Second',
  'Kilobits/Second',
  'Megabits/Second',
  'Gigabits/Second',
  'Terabits/Second',
  'Count/Second',
  'None',
];

/** A percentile statistic, e.g. `p99` or `p99.9` (p0 to p100). */
const PERCENTILE_RE = /^p(100(\.0{1,10})?|\d{1,2}(\.\d{1,10})?)$/;

/** An SNS topic ARN: `arn:<partition>:sns:<region>:<account>:<topic>` (standard or FIFO). */
const SNS_TOPIC_ARN_RE = /^arn:aws[a-z-]*:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]{1,256}(\.fifo)?$/;

const CONTROL_CHAR_RE = /[\x00-\x1F\x7F]/;

export function isSnsTopicArn(value: string): boolean {
  return SNS_TOPIC_ARN_RE.test(value);
}

/** Whether a period (seconds) is one CloudWatch alarms accept. */
export function isValidCloudWatchPeriod(period: number): boolean {
  if (!Number.isInteger(period) || period <= 0) return false;
  if (period < 60) return CLOUDWATCH_HIGH_RESOLUTION_PERIODS.includes(period);
  return period % 60 === 0 && period <= CLOUDWATCH_PERIOD_MAX_SECONDS;
}

function checkText(
  errors: Record<string, string>,
  field: string,
  label: string,
  value: unknown,
  max: number,
  required: boolean
): void {
  if (value === undefined || value === null || value === '') {
    if (required) errors[field] = `${label} is required`;
    return;
  }
  if (typeof value !== 'string') {
    errors[field] = `${label} must be text`;
  } else if (required && !value.trim()) {
    errors[field] = `${label} is required`;
  } else if (value.length > max) {
    errors[field] = `${label} must be ${max} characters or fewer`;
  } else if (CONTROL_CHAR_RE.test(value)) {
    errors[field] = `${label} must not contain control characters`;
  }
}

function checkActions(errors: Record<string, string>, field: string, actions: unknown): void {
  if (actions === undefined) return;
  if (!Array.isArray(actions)) {
    errors[field] = 'Actions must be a list';
    return;
  }
  if (actions.length > CLOUDWATCH_ACTIONS_PER_STATE_MAX) {
    errors[field] = `At most ${CLOUDWATCH_ACTIONS_PER_STATE_MAX} actions are allowed`;
    return;
  }
  if (new Set(actions).size !== actions.length) {
    errors[field] = 'Each action may be listed only once';
    return;
  }
  const bad = actions.find((a) => typeof a !== 'string' || !isSnsTopicArn(a));
  if (bad !== undefined) {
    errors[field] = 'Only Amazon SNS topic ARNs are supported as alarm actions';
  }
}

/**
 * Validate an alarm before it is written. Field keys match `CloudWatchMetricAlarmInput`
 * (`dimensions.0.name`, `alarmActions`, …) so the form can show each error by its field.
 */
export function validateCloudWatchMetricAlarm(
  input: Partial<CloudWatchMetricAlarmInput>
): ValidationResult {
  const errors: Record<string, string> = {};

  checkText(errors, 'alarmName', 'Alarm name', input.alarmName, CLOUDWATCH_ALARM_NAME_MAX, true);
  checkText(
    errors,
    'description',
    'Description',
    input.description,
    CLOUDWATCH_ALARM_DESCRIPTION_MAX,
    false
  );
  checkText(errors, 'namespace', 'Namespace', input.namespace, CLOUDWATCH_NAMESPACE_MAX, true);
  if (!errors.namespace && typeof input.namespace === 'string' && input.namespace.includes(':')) {
    errors.namespace = 'Namespace must not contain ":"';
  }
  checkText(
    errors,
    'metricName',
    'Metric name',
    input.metricName,
    CLOUDWATCH_METRIC_NAME_MAX,
    true
  );

  const dimensions = input.dimensions ?? [];
  if (!Array.isArray(dimensions)) {
    errors.dimensions = 'Dimensions must be a list';
  } else {
    if (dimensions.length > CLOUDWATCH_DIMENSIONS_MAX) {
      errors.dimensions = `At most ${CLOUDWATCH_DIMENSIONS_MAX} dimensions are allowed`;
    }
    const names = new Set<string>();
    dimensions.forEach((d, i) => {
      checkText(
        errors,
        `dimensions.${i}.name`,
        'Dimension name',
        d?.name,
        CLOUDWATCH_DIMENSION_NAME_MAX,
        true
      );
      checkText(
        errors,
        `dimensions.${i}.value`,
        'Dimension value',
        d?.value,
        CLOUDWATCH_DIMENSION_VALUE_MAX,
        true
      );
      if (typeof d?.name === 'string') {
        if (names.has(d.name)) errors[`dimensions.${i}.name`] = 'Dimension names must be unique';
        names.add(d.name);
      }
    });
  }

  const hasStatistic = input.statistic !== undefined && input.statistic !== null;
  const hasExtended = input.extendedStatistic !== undefined && input.extendedStatistic !== null;
  if (hasStatistic === hasExtended) {
    errors.statistic = 'Choose a statistic or a percentile';
  } else if (hasStatistic && !CLOUDWATCH_STATISTICS.includes(input.statistic!)) {
    errors.statistic = 'Unknown statistic';
  } else if (hasExtended && !PERCENTILE_RE.test(String(input.extendedStatistic))) {
    errors.extendedStatistic = 'Percentile must look like p99 or p99.9 (p0 to p100)';
  }

  if (input.unit !== undefined && !CLOUDWATCH_UNITS.includes(input.unit)) {
    errors.unit = 'Unknown unit';
  }

  const period = input.period;
  if (typeof period !== 'number' || !isValidCloudWatchPeriod(period)) {
    errors.period = 'Period must be 10, 20 or 30 seconds, or a multiple of 60 seconds up to 1 day';
  }

  const evaluationPeriods = input.evaluationPeriods;
  if (
    typeof evaluationPeriods !== 'number' ||
    !Number.isInteger(evaluationPeriods) ||
    evaluationPeriods < 1
  ) {
    errors.evaluationPeriods = 'Evaluation periods must be a whole number of at least 1';
  } else if (
    !errors.period &&
    (period as number) * evaluationPeriods > CLOUDWATCH_EVALUATION_WINDOW_MAX_SECONDS
  ) {
    errors.evaluationPeriods = 'Period × evaluation periods must be 7 days or less';
  }

  if (input.datapointsToAlarm !== undefined) {
    const m = input.datapointsToAlarm;
    if (typeof m !== 'number' || !Number.isInteger(m) || m < 1) {
      errors.datapointsToAlarm = 'Datapoints to alarm must be a whole number of at least 1';
    } else if (!errors.evaluationPeriods && m > (evaluationPeriods as number)) {
      errors.datapointsToAlarm = 'Datapoints to alarm cannot exceed evaluation periods';
    }
  }

  if (
    !input.comparisonOperator ||
    !CLOUDWATCH_COMPARISON_OPERATORS.includes(input.comparisonOperator)
  ) {
    errors.comparisonOperator = 'Choose a comparison';
  }
  if (typeof input.threshold !== 'number' || !Number.isFinite(input.threshold)) {
    errors.threshold = 'Threshold must be a number';
  }
  if (
    input.treatMissingData !== undefined &&
    !CLOUDWATCH_TREAT_MISSING_DATA.includes(input.treatMissingData)
  ) {
    errors.treatMissingData = 'Unknown missing-data treatment';
  }
  if (input.actionsEnabled !== undefined && typeof input.actionsEnabled !== 'boolean') {
    errors.actionsEnabled = 'Actions enabled must be true or false';
  }

  checkActions(errors, 'alarmActions', input.alarmActions);
  checkActions(errors, 'okActions', input.okActions);
  checkActions(errors, 'insufficientDataActions', input.insufficientDataActions);

  const tags = input.tags ?? [];
  if (!Array.isArray(tags)) {
    errors.tags = 'Tags must be a list';
  } else {
    if (tags.length > CLOUDWATCH_TAGS_MAX) {
      errors.tags = `At most ${CLOUDWATCH_TAGS_MAX} tags are allowed`;
    }
    const keys = new Set<string>();
    tags.forEach((t, i) => {
      checkText(errors, `tags.${i}.key`, 'Tag key', t?.key, CLOUDWATCH_TAG_KEY_MAX, true);
      if (t?.value === undefined || t?.value === null) {
        errors[`tags.${i}.value`] = 'Tag value is required (it may be empty)';
      } else {
        checkText(errors, `tags.${i}.value`, 'Tag value', t.value, CLOUDWATCH_TAG_VALUE_MAX, false);
      }
      if (typeof t?.key === 'string') {
        if (/^aws:/i.test(t.key)) errors[`tags.${i}.key`] = 'Tag keys must not start with "aws:"';
        else if (keys.has(t.key)) errors[`tags.${i}.key`] = 'Tag keys must be unique';
        keys.add(t.key);
      }
    });
  }

  return { valid: Object.keys(errors).length === 0, errors };
}

/**
 * Why this view can't edit an existing alarm, or undefined when it can. Editing rewrites the whole
 * alarm with `PutMetricAlarm`, so only alarms the form can reproduce exactly are editable;
 * anything else (composite, metric math, Metrics Insights, anomaly detection, non-SNS actions)
 * would silently lose settings. Those stay read-only here; delete and turning actions on or off
 * still work for any alarm.
 */
export function cloudWatchAlarmEditBlocker(alarm: CloudWatchAlarm): string | undefined {
  if (alarm.alarmType !== 'metric') return 'Composite alarms can only be edited in CloudWatch.';
  if (!alarm.namespace || !alarm.metricName) {
    return 'Alarms on metric math or Metrics Insights queries can only be edited in CloudWatch.';
  }
  if (
    !alarm.comparisonOperator ||
    !CLOUDWATCH_COMPARISON_OPERATORS.includes(
      alarm.comparisonOperator as CloudWatchComparisonOperator
    ) ||
    typeof alarm.threshold !== 'number'
  ) {
    return 'Anomaly detection alarms can only be edited in CloudWatch.';
  }
  const actions = [
    ...(alarm.alarmActions ?? []),
    ...(alarm.okActions ?? []),
    ...(alarm.insufficientDataActions ?? []),
  ];
  if (actions.some((a) => !isSnsTopicArn(a))) {
    return 'This alarm has actions other than SNS notifications, so it can only be edited in CloudWatch.';
  }
  return undefined;
}

/**
 * The write input that reproduces an editable alarm (see `cloudWatchAlarmEditBlocker`), to seed
 * the edit form. Tags aren't read back (CloudWatch ignores tags on an update anyway).
 */
export function cloudWatchAlarmToInput(alarm: CloudWatchAlarm): CloudWatchMetricAlarmInput {
  return {
    alarmName: alarm.alarmName,
    description: alarm.description,
    namespace: alarm.namespace ?? '',
    metricName: alarm.metricName ?? '',
    dimensions: (alarm.dimensions ?? []).map((d) => ({ name: d.name, value: d.value })),
    ...(alarm.extendedStatistic
      ? { extendedStatistic: alarm.extendedStatistic }
      : { statistic: (alarm.statistic as CloudWatchStatistic) ?? 'Average' }),
    period: alarm.period ?? 300,
    unit: alarm.unit,
    evaluationPeriods: alarm.evaluationPeriods ?? 1,
    datapointsToAlarm: alarm.datapointsToAlarm,
    comparisonOperator: alarm.comparisonOperator as CloudWatchComparisonOperator,
    threshold: alarm.threshold as number,
    treatMissingData: alarm.treatMissingData as CloudWatchTreatMissingData | undefined,
    actionsEnabled: alarm.actionsEnabled,
    alarmActions: alarm.alarmActions ?? [],
    okActions: alarm.okActions ?? [],
    insufficientDataActions: alarm.insufficientDataActions ?? [],
  };
}
