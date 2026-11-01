/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { CloudWatchMetricAlarmInput } from '../../../types/alerting';
import {
  cloudWatchAlarmEditBlocker,
  cloudWatchAlarmToInput,
  isSnsTopicArn,
  isValidCloudWatchPeriod,
  validateCloudWatchMetricAlarm,
} from '../cloudwatch_alarm_validator';

const valid = (overrides: Partial<CloudWatchMetricAlarmInput> = {}) => ({
  alarmName: 'checkout-errors-high',
  namespace: 'AWS/ApplicationELB',
  metricName: 'HTTPCode_Target_5XX_Count',
  dimensions: [{ name: 'LoadBalancer', value: 'app/checkout/abc' }],
  statistic: 'Sum' as const,
  period: 60,
  evaluationPeriods: 5,
  datapointsToAlarm: 3,
  comparisonOperator: 'GreaterThanThreshold' as const,
  threshold: 10,
  treatMissingData: 'notBreaching' as const,
  alarmActions: ['arn:aws:sns:us-east-1:123456789012:oncall'],
  tags: [{ key: 'team', value: 'checkout' }],
  ...overrides,
});

const errorsOf = (overrides: Partial<CloudWatchMetricAlarmInput>) =>
  validateCloudWatchMetricAlarm(valid(overrides)).errors;

describe('validateCloudWatchMetricAlarm', () => {
  it('accepts a complete single-metric alarm', () => {
    expect(validateCloudWatchMetricAlarm(valid())).toEqual({ valid: true, errors: {} });
    expect(
      validateCloudWatchMetricAlarm(valid({ statistic: undefined, extendedStatistic: 'p99.9' }))
        .valid
    ).toBe(true);
  });

  it('requires a name, namespace and metric, without control characters', () => {
    expect(errorsOf({ alarmName: '' }).alarmName).toBeDefined();
    expect(errorsOf({ alarmName: '   ' }).alarmName).toBeDefined();
    expect(errorsOf({ alarmName: 'a'.repeat(256) }).alarmName).toBeDefined();
    expect(errorsOf({ alarmName: 'bad\nname' }).alarmName).toBeDefined();
    expect(errorsOf({ namespace: '' }).namespace).toBeDefined();
    expect(errorsOf({ namespace: 'a:b' }).namespace).toBeDefined();
    expect(errorsOf({ metricName: '' }).metricName).toBeDefined();
  });

  it('allows the names CloudWatch allows', () => {
    expect(errorsOf({ alarmName: 'TargetTracking-table/MyTable (p99)' }).alarmName).toBeUndefined();
  });

  it('needs exactly one of statistic and percentile', () => {
    expect(errorsOf({ statistic: undefined }).statistic).toBeDefined();
    expect(errorsOf({ extendedStatistic: 'p99' }).statistic).toBeDefined();
    expect(errorsOf({ statistic: 'Median' as never }).statistic).toBeDefined();
    expect(
      errorsOf({ statistic: undefined, extendedStatistic: 'p101' }).extendedStatistic
    ).toBeDefined();
    expect(
      errorsOf({ statistic: undefined, extendedStatistic: 'tm99' }).extendedStatistic
    ).toBeDefined();
  });

  it('checks periods, evaluation periods and M out of N', () => {
    expect(isValidCloudWatchPeriod(10)).toBe(true);
    expect(isValidCloudWatchPeriod(300)).toBe(true);
    expect(isValidCloudWatchPeriod(45)).toBe(false);
    expect(isValidCloudWatchPeriod(90)).toBe(false);
    expect(isValidCloudWatchPeriod(86460)).toBe(false);
    expect(errorsOf({ evaluationPeriods: 0 }).evaluationPeriods).toBeDefined();
    expect(errorsOf({ period: 86400, evaluationPeriods: 8 }).evaluationPeriods).toBeDefined();
    expect(errorsOf({ datapointsToAlarm: 6 }).datapointsToAlarm).toBeDefined();
    expect(errorsOf({ datapointsToAlarm: 0 }).datapointsToAlarm).toBeDefined();
  });

  it('needs a known comparison and a finite threshold', () => {
    expect(
      errorsOf({ comparisonOperator: 'GreaterThanUpperThreshold' as never }).comparisonOperator
    ).toBeDefined();
    expect(errorsOf({ threshold: Number.NaN }).threshold).toBeDefined();
    expect(errorsOf({ threshold: Infinity }).threshold).toBeDefined();
    expect(errorsOf({ treatMissingData: 'zero' as never }).treatMissingData).toBeDefined();
  });

  it('allows only SNS topics as actions, at most 5 per state', () => {
    expect(isSnsTopicArn('arn:aws:sns:us-west-2:123456789012:alerts.fifo')).toBe(true);
    expect(isSnsTopicArn('arn:aws-us-gov:sns:us-gov-west-1:123456789012:alerts')).toBe(true);
    for (const action of [
      'arn:aws:automate:us-east-1:ec2:terminate',
      'arn:aws:automate:us-east-1:ec2:stop',
      'arn:aws:swf:us-east-1:123456789012:action/actions/AWS_EC2.InstanceId.Reboot/1.0',
      'arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:x',
      'arn:aws:lambda:us-east-1:123456789012:function:f',
      'arn:aws:ssm:us-east-1:123456789012:opsitem:3',
    ]) {
      expect(errorsOf({ alarmActions: [action] }).alarmActions).toBeDefined();
    }
    const topic = (i: number) => `arn:aws:sns:us-east-1:123456789012:t${i}`;
    expect(errorsOf({ okActions: [0, 1, 2, 3, 4, 5].map(topic) }).okActions).toBeDefined();
    expect(
      errorsOf({ insufficientDataActions: [topic(1), topic(1)] }).insufficientDataActions
    ).toBeDefined();
  });

  it('checks dimensions and tags', () => {
    expect(errorsOf({ dimensions: [{ name: '', value: 'x' }] })['dimensions.0.name']).toBeDefined();
    expect(
      errorsOf({
        dimensions: [
          { name: 'a', value: '1' },
          { name: 'a', value: '2' },
        ],
      })['dimensions.1.name']
    ).toBeDefined();
    expect(errorsOf({ tags: [{ key: 'aws:createdBy', value: 'x' }] })['tags.0.key']).toBeDefined();
    expect(errorsOf({ tags: [{ key: 'empty', value: '' }] })['tags.0.value']).toBeUndefined();
    expect(
      errorsOf({
        dimensions: Array.from({ length: 31 }, (_, i) => ({ name: `d${i}`, value: 'v' })),
      }).dimensions
    ).toBeDefined();
  });
});

describe('cloudWatchAlarmEditBlocker / cloudWatchAlarmToInput', () => {
  const alarm = {
    alarmName: 'cpu-high',
    alarmType: 'metric' as const,
    stateValue: 'OK' as const,
    namespace: 'AWS/EC2',
    metricName: 'CPUUtilization',
    dimensions: [{ name: 'InstanceId', value: 'i-1' }],
    statistic: 'Average',
    period: 300,
    evaluationPeriods: 3,
    datapointsToAlarm: 2,
    comparisonOperator: 'GreaterThanThreshold',
    threshold: 80,
    treatMissingData: 'missing',
    actionsEnabled: true,
    alarmActions: ['arn:aws:sns:us-east-1:123456789012:oncall'],
  };

  it('lets the form edit a single-metric static alarm and reproduces it exactly', () => {
    expect(cloudWatchAlarmEditBlocker(alarm)).toBeUndefined();
    const input = cloudWatchAlarmToInput(alarm);
    expect(validateCloudWatchMetricAlarm(input)).toEqual({ valid: true, errors: {} });
    expect(input).toMatchObject({
      statistic: 'Average',
      evaluationPeriods: 3,
      datapointsToAlarm: 2,
    });
  });

  it('keeps alarms the form would rewrite lossily read-only', () => {
    expect(cloudWatchAlarmEditBlocker({ ...alarm, alarmType: 'composite' })).toMatch(/Composite/);
    expect(cloudWatchAlarmEditBlocker({ ...alarm, namespace: undefined })).toMatch(/metric math/);
    expect(
      cloudWatchAlarmEditBlocker({
        ...alarm,
        comparisonOperator: 'LessThanLowerOrGreaterThanUpperThreshold',
        threshold: undefined,
      })
    ).toMatch(/Anomaly/);
    expect(
      cloudWatchAlarmEditBlocker({
        ...alarm,
        alarmActions: ['arn:aws:automate:us-east-1:ec2:stop'],
      })
    ).toMatch(/other than SNS/);
  });
});
