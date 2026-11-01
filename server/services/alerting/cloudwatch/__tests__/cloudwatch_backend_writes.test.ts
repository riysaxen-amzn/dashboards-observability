/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CloudWatchBackend writes: the per-request gate (writes flag and a source that can write),
 * server-side validation, the name-taken check before an upsert, edit only for alarms the form
 * can reproduce, and not-found on stale rows.
 */
import type {
  CloudWatchAlarm,
  CloudWatchAlarmSource,
  CloudWatchMetricAlarmInput,
  Datasource,
} from '../../../../../common/types/alerting';
import { CloudWatchBackend } from '../cloudwatch_backend';

const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
const ds = {
  id: 'cloudwatch',
  name: 'CloudWatch',
  type: 'cloudwatch',
  region: 'us-west-2',
} as Datasource;

const input = (
  overrides: Partial<CloudWatchMetricAlarmInput> = {}
): CloudWatchMetricAlarmInput => ({
  alarmName: 'cpu-high',
  namespace: 'AWS/EC2',
  metricName: 'CPUUtilization',
  dimensions: [{ name: 'InstanceId', value: 'i-1' }],
  statistic: 'Average',
  period: 300,
  evaluationPeriods: 3,
  comparisonOperator: 'GreaterThanThreshold',
  threshold: 80,
  alarmActions: ['arn:aws:sns:us-west-2:123456789012:oncall'],
  tags: [{ key: 'team', value: 'infra' }],
  ...overrides,
});

const metricAlarm = (overrides: Partial<CloudWatchAlarm> = {}): CloudWatchAlarm => ({
  alarmName: 'cpu-high',
  alarmType: 'metric',
  stateValue: 'OK',
  namespace: 'AWS/EC2',
  metricName: 'CPUUtilization',
  comparisonOperator: 'GreaterThanThreshold',
  threshold: 80,
  ...overrides,
});

function makeSource(existing: CloudWatchAlarm | null, writable = true) {
  const source = {
    getCallerIdentity: jest.fn(),
    describeAlarms: jest.fn(),
    describeAlarm: jest.fn(async () => existing),
    describeAlarmsByName: jest.fn(),
    describeParentAlarms: jest.fn(),
    describeAlarmHistory: jest.fn(),
    describeStateChanges: jest.fn(),
    getMetricData: jest.fn(),
    listMetrics: jest.fn(async () => ({ metrics: [], nextToken: 'n' })),
    ...(writable
      ? {
          putMetricAlarm: jest.fn(async () => undefined),
          deleteAlarms: jest.fn(async () => undefined),
          setAlarmActionsEnabled: jest.fn(async () => undefined),
        }
      : {}),
  };
  return source as typeof source & CloudWatchAlarmSource;
}

const backend = (source: CloudWatchAlarmSource, writesEnabled = true) =>
  new CloudWatchBackend(logger, source, { writesEnabled });

describe('CloudWatchBackend writes — gate', () => {
  it('writes only with the flag on and a source that can write', async () => {
    expect(backend(makeSource(null)).canWrite).toBe(true);
    expect(backend(makeSource(null), false).canWrite).toBe(false);
    expect(backend(makeSource(null, false)).canWrite).toBe(false);
    expect(new CloudWatchBackend(logger, makeSource(null)).canWrite).toBe(false);

    const source = makeSource(null);
    await expect(backend(source, false).createMetricAlarm(ds, input())).rejects.toMatchObject({
      kind: 'not_found',
    });
    await expect(backend(source, false).deleteAlarm(ds, 'cpu-high')).rejects.toMatchObject({
      kind: 'not_found',
    });
    expect(source.describeAlarm).not.toHaveBeenCalled();
    expect(source.putMetricAlarm).not.toHaveBeenCalled();
  });
});

describe('CloudWatchBackend writes — create', () => {
  it('writes a valid alarm whose name is free, in the datasource region', async () => {
    const source = makeSource(null);
    const { signal } = new AbortController();
    await backend(source).createMetricAlarm(ds, input(), { signal });
    expect(source.describeAlarm).toHaveBeenCalledWith('cpu-high', 'us-west-2', { signal });
    expect(source.putMetricAlarm).toHaveBeenCalledWith(input(), 'us-west-2', { signal });
  });

  it('refuses a taken name instead of overwriting it', async () => {
    const source = makeSource(metricAlarm());
    await expect(backend(source).createMetricAlarm(ds, input())).rejects.toMatchObject({
      kind: 'conflict',
    });
    expect(source.putMetricAlarm).not.toHaveBeenCalled();
  });

  it('validates on the server, before any call', async () => {
    const source = makeSource(null);
    await expect(
      backend(source).createMetricAlarm(
        ds,
        input({ alarmActions: ['arn:aws:automate:us-west-2:ec2:terminate'] })
      )
    ).rejects.toMatchObject({ kind: 'validation', field: 'alarmActions' });
    expect(source.describeAlarm).not.toHaveBeenCalled();
  });
});

describe('CloudWatchBackend writes — update, delete, actions', () => {
  it('updates an editable alarm without tags (CloudWatch ignores them on update)', async () => {
    const source = makeSource(metricAlarm());
    await backend(source).updateMetricAlarm(ds, input());
    const { tags, ...withoutTags } = input();
    expect(tags).toBeDefined();
    expect(source.putMetricAlarm).toHaveBeenCalledWith(withoutTags, 'us-west-2', undefined);
  });

  it('refuses to edit an alarm the form would rewrite lossily, or one that is gone', async () => {
    const composite = makeSource(metricAlarm({ alarmType: 'composite' }));
    await expect(backend(composite).updateMetricAlarm(ds, input())).rejects.toMatchObject({
      kind: 'validation',
    });
    expect(composite.putMetricAlarm).not.toHaveBeenCalled();
    await expect(backend(makeSource(null)).updateMetricAlarm(ds, input())).rejects.toMatchObject({
      kind: 'not_found',
    });
  });

  it('deletes and toggles actions on any existing alarm, and 404s a stale one', async () => {
    const source = makeSource(metricAlarm({ alarmType: 'composite' }));
    await backend(source).deleteAlarm(ds, 'cpu-high');
    expect(source.deleteAlarms).toHaveBeenCalledWith(['cpu-high'], 'us-west-2', undefined);
    await backend(source).setAlarmActionsEnabled(ds, 'cpu-high', false);
    expect(source.setAlarmActionsEnabled).toHaveBeenCalledWith(
      ['cpu-high'],
      false,
      'us-west-2',
      undefined
    );
    const gone = makeSource(null);
    await expect(backend(gone).deleteAlarm(ds, 'x')).rejects.toMatchObject({ kind: 'not_found' });
    expect(gone.deleteAlarms).not.toHaveBeenCalled();
  });

  it('lists metrics in the datasource region when the source can', async () => {
    const source = makeSource(null);
    await expect(backend(source).listMetrics(ds, { namespace: 'AWS/EC2' })).resolves.toEqual({
      metrics: [],
      nextToken: 'n',
    });
    expect(source.listMetrics).toHaveBeenCalledWith(
      { namespace: 'AWS/EC2', region: 'us-west-2' },
      undefined
    );
  });
});
