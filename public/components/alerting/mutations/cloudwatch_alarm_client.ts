/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * HTTP calls for CloudWatch alarm writes and the create form's metric list. The routes refuse
 * (404) unless writes are on for the request, so the UI also checks
 * `coreRefs.cloudwatchWritesEnabled` before offering them. Alarms are addressed by name (a
 * query value: names may contain `/`), never by the row id.
 */
import type {
  CloudWatchMetricAlarmInput,
  CloudWatchMetricList,
} from '../../../../common/types/alerting';
import { coreRefs } from '../../../framework/core_refs';

const base = (dsId: string) => `/api/alerting/cloudwatch/${encodeURIComponent(dsId)}`;

function http() {
  const client = coreRefs.http;
  if (!client) throw new Error('HTTP client not available');
  return client;
}

export function createCloudWatchAlarm(dsId: string, input: CloudWatchMetricAlarmInput) {
  return http().post(`${base(dsId)}/alarms`, { body: JSON.stringify(input) });
}

export function updateCloudWatchAlarm(dsId: string, input: CloudWatchMetricAlarmInput) {
  return http().put(`${base(dsId)}/alarm`, {
    query: { name: input.alarmName },
    body: JSON.stringify(input),
  });
}

export function deleteCloudWatchAlarm(dsId: string, alarmName: string) {
  return http().delete(`${base(dsId)}/alarm`, { query: { name: alarmName } });
}

export function setCloudWatchAlarmActionsEnabled(
  dsId: string,
  alarmName: string,
  enabled: boolean
) {
  return http().post(`${base(dsId)}/alarm/actions`, {
    query: { name: alarmName },
    body: JSON.stringify({ enabled }),
  });
}

export async function listCloudWatchMetrics(
  dsId: string,
  query: { namespace?: string; metricName?: string; nextToken?: string }
): Promise<CloudWatchMetricList> {
  const clean = Object.fromEntries(Object.entries(query).filter(([, v]) => !!v));
  return (await http().get(`${base(dsId)}/metrics`, { query: clean })) as CloudWatchMetricList;
}
