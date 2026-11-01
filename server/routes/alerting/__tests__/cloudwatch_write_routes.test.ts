/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CloudWatch write routes, driven through their registered handlers: 404 unless writes are on
 * for the request, our own refusals keep their fixed message (and field), CloudWatch failures
 * are classified without provider text, and the body schema refuses unknown fields.
 */
import { CloudWatchBackend } from '../../../services/alerting/cloudwatch/cloudwatch_backend';
import { registerAlertingRoutes } from '../index';
import { registerDefaultClassifiers } from '../../../../common/error';

// The plugin registers these at setup.
beforeAll(() => registerDefaultClassifiers());

const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

type Handler = (ctx: unknown, req: unknown, res: unknown) => Promise<unknown>;

function setup(opts: { writesEnabled?: boolean; existing?: unknown; putError?: Error } = {}) {
  const routes: Record<string, { config: any; handler: Handler }> = {};
  const add = (method: string) =>
    jest.fn((config: any, handler: Handler) => {
      routes[`${method} ${config.path}`] = { config, handler };
    });
  const router = { get: add('GET'), post: add('POST'), put: add('PUT'), delete: add('DELETE') };
  const source: any = {
    getCallerIdentity: jest.fn(),
    describeAlarms: jest.fn(),
    describeAlarm: jest.fn(async () => opts.existing ?? null),
    describeAlarmsByName: jest.fn(),
    describeParentAlarms: jest.fn(),
    describeAlarmHistory: jest.fn(),
    describeStateChanges: jest.fn(),
    getMetricData: jest.fn(),
    listMetrics: jest.fn(async () => ({ metrics: [] })),
    putMetricAlarm: jest.fn(async () => {
      if (opts.putError) throw opts.putError;
    }),
    deleteAlarms: jest.fn(async () => undefined),
    setAlarmActionsEnabled: jest.fn(async () => undefined),
  };
  registerAlertingRoutes(router as never, {
    osBackend: {} as never,
    promBackend: {} as never,
    mutationSvc: {} as never,
    logger,
    cwBackend: async () =>
      new CloudWatchBackend(logger, source, { writesEnabled: opts.writesEnabled ?? true }),
    cloudWatchRegion: 'us-west-2',
  });
  const res = {
    ok: jest.fn((r) => ({ status: 200, ...r })),
    customError: jest.fn((r) => ({ status: r.statusCode, ...r })),
  };
  const ctx = { core: { savedObjects: { client: {} } } };
  const call = (key: string, req: Record<string, unknown>) =>
    routes[key].handler(
      ctx,
      { headers: {}, params: { dsId: 'cloudwatch' }, query: {}, ...req },
      res
    );
  return { routes, source, call };
}

const alarm = {
  alarmName: 'cpu-high',
  namespace: 'AWS/EC2',
  metricName: 'CPUUtilization',
  statistic: 'Average',
  period: 300,
  evaluationPeriods: 3,
  comparisonOperator: 'GreaterThanThreshold',
  threshold: 80,
  alarmActions: ['arn:aws:sns:us-west-2:123456789012:oncall'],
};

beforeEach(() => jest.clearAllMocks());

describe('CloudWatch write routes', () => {
  it('registers create, update, delete, actions and the metric listing', () => {
    const { routes } = setup();
    expect(Object.keys(routes)).toEqual(
      expect.arrayContaining([
        'POST /api/alerting/cloudwatch/{dsId}/alarms',
        'PUT /api/alerting/cloudwatch/{dsId}/alarm',
        'DELETE /api/alerting/cloudwatch/{dsId}/alarm',
        'POST /api/alerting/cloudwatch/{dsId}/alarm/actions',
        'GET /api/alerting/cloudwatch/{dsId}/metrics',
      ])
    );
  });

  it('creates an alarm', async () => {
    const { call, source } = setup();
    const out: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarms', { body: alarm });
    expect(out.status).toBe(200);
    expect(out.body).toEqual({ alarmName: 'cpu-high' });
    expect(source.putMetricAlarm).toHaveBeenCalledWith(alarm, 'us-west-2', expect.anything());
  });

  it('answers 404 to every write when writes are off for the request', async () => {
    const { call, source } = setup({ writesEnabled: false });
    const create: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarms', { body: alarm });
    const del: any = await call('DELETE /api/alerting/cloudwatch/{dsId}/alarm', {
      query: { name: 'cpu-high' },
    });
    const metrics: any = await call('GET /api/alerting/cloudwatch/{dsId}/metrics', { query: {} });
    expect([create.status, del.status, metrics.status]).toEqual([404, 404, 404]);
    expect(source.putMetricAlarm).not.toHaveBeenCalled();
    expect(source.deleteAlarms).not.toHaveBeenCalled();
  });

  it('keeps our own refusal messages and the field, and logs only the kind', async () => {
    const { call } = setup({
      existing: { alarmName: 'cpu-high', alarmType: 'metric', stateValue: 'OK' },
    });
    const taken: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarms', { body: alarm });
    expect(taken.status).toBe(409);
    expect(taken.body.message).toContain('already exists');
    const bad: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarms', {
      body: { ...alarm, alarmName: 'other', alarmActions: ['arn:aws:automate:us-west-2:ec2:stop'] },
    });
    expect(bad.status).toBe(400);
    expect(bad.body.attributes).toEqual({ field: 'alarmActions' });
    expect(logger.warn.mock.calls.flat().join(' ')).not.toContain('cpu-high');
  });

  it('refuses a rename on update', async () => {
    const { call, source } = setup({
      existing: { alarmName: 'cpu-high', alarmType: 'metric', stateValue: 'OK' },
    });
    const out: any = await call('PUT /api/alerting/cloudwatch/{dsId}/alarm', {
      query: { name: 'cpu-high' },
      body: { ...alarm, alarmName: 'renamed' },
    });
    expect(out.status).toBe(400);
    expect(source.putMetricAlarm).not.toHaveBeenCalled();
  });

  it('classifies a CloudWatch failure without passing its text on', async () => {
    const denied = Object.assign(
      new Error('User: arn:aws:sts::123456789012:assumed-role/x is not authorized'),
      { name: 'AccessDeniedException', $metadata: { httpStatusCode: 403 } }
    );
    const { call } = setup({ putError: denied });
    const out: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarms', { body: alarm });
    expect(out.status).toBe(403);
    expect(JSON.stringify(out.body)).not.toContain('123456789012:assumed-role');
    expect(out.body.attributes.errorDetail.remediation).toContain('cloudwatch:PutMetricAlarm');
    expect(logger.error.mock.calls.flat().join(' ')).not.toContain('assumed-role');
  });

  it('toggles actions and deletes', async () => {
    const { call, source } = setup({
      existing: { alarmName: 'x', alarmType: 'composite', stateValue: 'OK' },
    });
    const toggled: any = await call('POST /api/alerting/cloudwatch/{dsId}/alarm/actions', {
      query: { name: 'x' },
      body: { enabled: false },
    });
    expect(toggled.status).toBe(200);
    expect(source.setAlarmActionsEnabled).toHaveBeenCalledWith(
      ['x'],
      false,
      'us-west-2',
      expect.anything()
    );
    const deleted: any = await call('DELETE /api/alerting/cloudwatch/{dsId}/alarm', {
      query: { name: 'x' },
    });
    expect(deleted.status).toBe(200);
    expect(source.deleteAlarms).toHaveBeenCalledWith(['x'], 'us-west-2', expect.anything());
  });

  it('refuses unknown body fields at the schema', () => {
    const { routes } = setup();
    const body = routes['POST /api/alerting/cloudwatch/{dsId}/alarms'].config.validate.body;
    expect(() => body.validate(alarm)).not.toThrow();
    expect(() => body.validate({ ...alarm, Metrics: [] })).toThrow();
    expect(() => body.validate({ ...alarm, alarmActions: Array(6).fill('a') })).toThrow();
  });
});
