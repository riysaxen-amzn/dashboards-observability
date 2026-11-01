/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CloudWatch alarm writes in the UI: the create/edit form (validation, the request it sends,
 * server refusals shown on the field or as a callout) and the detail flyout's actions (shown only
 * with writes on; edit only for alarms the form can reproduce; delete asks first).
 */
import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { I18nProvider } from '@osd/i18n/react';
import type { CloudWatchAlarmDetail } from '../../../../common/types/alerting';
import { coreRefs } from '../../../framework/core_refs';
import { CreateCloudWatchAlarm, toInput } from '../create_cloudwatch_alarm';
import { CloudWatchAlarmDetailFlyout } from '../cloudwatch_alarm_detail_flyout';
import { useCloudWatchAlarmDetail } from '../hooks/use_cloudwatch_alarm_detail';
import * as client from '../mutations/cloudwatch_alarm_client';

jest.mock('../hooks/use_cloudwatch_alarm_detail', () => ({ useCloudWatchAlarmDetail: jest.fn() }));
jest.mock('../echarts_render', () => ({ EchartsRender: () => <div /> }));
jest.mock('../mutations/cloudwatch_alarm_client', () => ({
  createCloudWatchAlarm: jest.fn(async () => ({})),
  updateCloudWatchAlarm: jest.fn(async () => ({})),
  deleteCloudWatchAlarm: jest.fn(async () => ({})),
  setCloudWatchAlarmActionsEnabled: jest.fn(async () => ({})),
  listCloudWatchMetrics: jest.fn(async () => ({
    metrics: [
      {
        namespace: 'AWS/EC2',
        metricName: 'CPUUtilization',
        dimensions: [{ name: 'InstanceId', value: 'i-1' }],
      },
    ],
  })),
}));

const mocked = client as jest.Mocked<typeof client>;
const toasts = { addSuccess: jest.fn(), addDanger: jest.fn() };

beforeEach(() => {
  jest.clearAllMocks();
  coreRefs.toasts = toasts as never;
  coreRefs.cloudwatchWritesEnabled = true;
});

const withIntl = (ui: React.ReactElement) => render(<I18nProvider>{ui}</I18nProvider>);

const editInput = {
  alarmName: 'cpu-high',
  namespace: 'AWS/EC2',
  metricName: 'CPUUtilization',
  dimensions: [{ name: 'InstanceId', value: 'i-1' }],
  statistic: 'Average' as const,
  period: 300,
  evaluationPeriods: 3,
  comparisonOperator: 'GreaterThanThreshold' as const,
  threshold: 80,
  treatMissingData: 'missing' as const,
  actionsEnabled: true,
  alarmActions: ['arn:aws:sns:us-west-2:123456789012:oncall'],
  okActions: [],
};

describe('CreateCloudWatchAlarm', () => {
  it('builds the write input from the form, with tags only on create', () => {
    const form = {
      alarmName: ' cpu ',
      description: '',
      namespace: 'AWS/EC2',
      metricName: 'CPUUtilization',
      dimensions: [],
      statistic: 'percentile' as const,
      percentile: 'p99',
      period: '60',
      evaluationPeriods: '5',
      datapointsToAlarm: '3',
      comparisonOperator: 'GreaterThanThreshold' as const,
      threshold: '90',
      treatMissingData: 'missing' as const,
      actionsEnabled: true,
      alarmActions: [],
      okActions: [],
      tags: [{ key: 'team', value: 'x' }],
    };
    expect(toInput(form, 'create')).toMatchObject({
      alarmName: 'cpu',
      extendedStatistic: 'p99',
      period: 60,
      evaluationPeriods: 5,
      datapointsToAlarm: 3,
      threshold: 90,
      tags: [{ key: 'team', value: 'x' }],
    });
    expect(toInput(form, 'create').statistic).toBeUndefined();
    expect(toInput(form, 'edit').tags).toBeUndefined();
  });

  it('shows field errors instead of sending an invalid alarm', async () => {
    withIntl(<CreateCloudWatchAlarm dsId="cloudwatch" onClose={jest.fn()} onSaved={jest.fn()} />);
    fireEvent.click(screen.getByTestId('cloudWatchAlarm-save'));
    expect(await screen.findByText('Alarm name is required')).toBeInTheDocument();
    expect(screen.getByText('Threshold must be a number')).toBeInTheDocument();
    expect(mocked.createCloudWatchAlarm).not.toHaveBeenCalled();
  });

  it('warns about a name already in the list before asking the server', async () => {
    withIntl(
      <CreateCloudWatchAlarm
        dsId="cloudwatch"
        existingNames={['cpu-high']}
        onClose={jest.fn()}
        onSaved={jest.fn()}
      />
    );
    fireEvent.change(screen.getByTestId('cloudWatchAlarm-alarmName'), {
      target: { value: 'cpu-high' },
    });
    fireEvent.click(screen.getByTestId('cloudWatchAlarm-save'));
    expect(await screen.findByText('An alarm with this name already exists')).toBeInTheDocument();
    expect(mocked.createCloudWatchAlarm).not.toHaveBeenCalled();
  });

  it('saves an edit through the update route and reports it', async () => {
    const onSaved = jest.fn();
    withIntl(
      <CreateCloudWatchAlarm
        dsId="cloudwatch"
        initial={editInput}
        onClose={jest.fn()}
        onSaved={onSaved}
      />
    );
    expect(screen.getByTestId('cloudWatchAlarm-alarmName')).toBeDisabled();
    fireEvent.change(screen.getByTestId('cloudWatchAlarm-threshold'), { target: { value: '95' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('cloudWatchAlarm-save'));
    });
    expect(mocked.updateCloudWatchAlarm).toHaveBeenCalledWith(
      'cloudwatch',
      expect.objectContaining({ alarmName: 'cpu-high', threshold: 95 })
    );
    expect(mocked.updateCloudWatchAlarm.mock.calls[0][1].tags).toBeUndefined();
    expect(onSaved).toHaveBeenCalledWith('cpu-high', 'edit');
  });

  it('shows a server refusal on its field', async () => {
    mocked.updateCloudWatchAlarm.mockRejectedValueOnce({
      body: {
        message: 'Composite alarms can only be edited in CloudWatch.',
        attributes: { field: 'alarmName' },
      },
    });
    withIntl(
      <CreateCloudWatchAlarm
        dsId="cloudwatch"
        initial={editInput}
        onClose={jest.fn()}
        onSaved={jest.fn()}
      />
    );
    await act(async () => {
      fireEvent.click(screen.getByTestId('cloudWatchAlarm-save'));
    });
    expect(
      screen.getByText('Composite alarms can only be edited in CloudWatch.')
    ).toBeInTheDocument();
  });

  it('shows a classified CloudWatch failure with its remediation', async () => {
    mocked.updateCloudWatchAlarm.mockRejectedValueOnce({
      body: {
        message: 'denied',
        attributes: {
          errorDetail: {
            category: 'PERMISSION_DENIED',
            code: 'CLOUDWATCH_ACCESS_DENIED',
            title: 'CloudWatch change denied',
            message: "Your AWS identity isn't allowed to make this change to CloudWatch alarms.",
            remediation: 'Ask an administrator to grant your identity cloudwatch:PutMetricAlarm.',
            retryable: false,
          },
        },
      },
    });
    withIntl(
      <CreateCloudWatchAlarm
        dsId="cloudwatch"
        initial={editInput}
        onClose={jest.fn()}
        onSaved={jest.fn()}
      />
    );
    await act(async () => {
      fireEvent.click(screen.getByTestId('cloudWatchAlarm-save'));
    });
    expect(screen.getByText('CloudWatch change denied')).toBeInTheDocument();
  });
});

describe('CloudWatchAlarmDetailFlyout write actions', () => {
  const row = {
    id: 'arn:aws:cloudwatch:us-west-2:123456789012:alarm:cpu-high',
    name: 'cpu-high',
    datasourceId: 'cloudwatch',
    monitorType: 'metric',
    cloudWatch: { state: 'OK' as const, alarmType: 'metric' as const, alarmName: 'cpu-high' },
  };
  const detail = (alarm: Partial<CloudWatchAlarmDetail['alarm']> = {}): CloudWatchAlarmDetail => ({
    alarm: {
      alarmName: 'cpu-high',
      alarmType: 'metric',
      stateValue: 'OK',
      namespace: 'AWS/EC2',
      metricName: 'CPUUtilization',
      statistic: 'Average',
      period: 300,
      evaluationPeriods: 3,
      comparisonOperator: 'GreaterThanThreshold',
      threshold: 80,
      actionsEnabled: true,
      ...alarm,
    },
    summary: 'cpu-high is OK.',
    history: [],
    historyAccessDenied: false,
  });
  const mockDetail = (d: CloudWatchAlarmDetail) =>
    (useCloudWatchAlarmDetail as jest.Mock).mockReturnValue({
      detail: d,
      isLoading: false,
      error: null,
      classifiedError: null,
      retry: jest.fn(),
      windowRejected: false,
    });

  it('stays read-only without writes', () => {
    coreRefs.cloudwatchWritesEnabled = false;
    mockDetail(detail());
    withIntl(
      <CloudWatchAlarmDetailFlyout rule={row as never} onClose={jest.fn()} onEdit={jest.fn()} />
    );
    expect(screen.getByTestId('cwAlarmReadOnlyBadge')).toBeInTheDocument();
    expect(screen.queryByTestId('cwAlarmDelete')).not.toBeInTheDocument();
  });

  it('opens the edit form with the alarm reproduced, and turns notifications off', async () => {
    mockDetail(detail());
    const onEdit = jest.fn();
    const onChanged = jest.fn();
    withIntl(
      <CloudWatchAlarmDetailFlyout
        rule={row as never}
        onClose={jest.fn()}
        onEdit={onEdit}
        onChanged={onChanged}
      />
    );
    expect(screen.queryByTestId('cwAlarmReadOnlyBadge')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('cwAlarmEdit'));
    expect(onEdit).toHaveBeenCalledWith(
      expect.objectContaining({ alarmName: 'cpu-high', threshold: 80 })
    );
    await act(async () => {
      fireEvent.click(screen.getByTestId('cwAlarmToggleActions'));
    });
    expect(mocked.setCloudWatchAlarmActionsEnabled).toHaveBeenCalledWith(
      'cloudwatch',
      'cpu-high',
      false
    );
    expect(onChanged).toHaveBeenCalledWith('actions');
  });

  it('disables edit for alarms the form would rewrite lossily', () => {
    mockDetail(detail({ alarmType: 'composite', alarmRule: 'ALARM("x")' }));
    withIntl(
      <CloudWatchAlarmDetailFlyout rule={row as never} onClose={jest.fn()} onEdit={jest.fn()} />
    );
    expect(screen.getByTestId('cwAlarmEdit')).toBeDisabled();
  });

  it('asks before deleting, then deletes by alarm name and closes', async () => {
    mockDetail(detail());
    const onClose = jest.fn();
    const onChanged = jest.fn();
    withIntl(
      <CloudWatchAlarmDetailFlyout rule={row as never} onClose={onClose} onChanged={onChanged} />
    );
    fireEvent.click(screen.getByTestId('cwAlarmDelete'));
    expect(mocked.deleteCloudWatchAlarm).not.toHaveBeenCalled();
    await act(async () => {
      fireEvent.click(screen.getByText('Delete alarm'));
    });
    await waitFor(() =>
      expect(mocked.deleteCloudWatchAlarm).toHaveBeenCalledWith('cloudwatch', 'cpu-high')
    );
    expect(onChanged).toHaveBeenCalledWith('deleted');
    expect(onClose).toHaveBeenCalled();
  });
});
