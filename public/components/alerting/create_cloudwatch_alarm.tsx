/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Create or edit a CloudWatch metric alarm: one metric, a static threshold, SNS notifications.
 *
 * Field rules come from `validateCloudWatchMetricAlarm`, the same check the server runs. On save
 * the flyout calls the CloudWatch write routes itself and reports success to the parent, which
 * refetches the Rules tab. Server refusals show inline: our own (name taken, invalid field) on
 * the field, CloudWatch's (access denied, quota, rejected settings) as a callout with its
 * remediation.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { i18n } from '@osd/i18n';
import type {
  CloudWatchComparisonOperator,
  CloudWatchMetricAlarmInput,
  CloudWatchMetricRef,
  CloudWatchStatistic,
  CloudWatchTreatMissingData,
} from '../../../common/types/alerting';
import {
  CLOUDWATCH_STATISTICS,
  validateCloudWatchMetricAlarm,
} from '../../../common/services/alerting/cloudwatch_alarm_validator';
import type { ClassifiedError } from '../../../common/error';
import { ClassifiedErrorCallout, extractClassifiedError } from '../common/error';
import {
  createCloudWatchAlarm,
  listCloudWatchMetrics,
  updateCloudWatchAlarm,
} from './mutations/cloudwatch_alarm_client';

const t = (id: string, defaultMessage: string, values?: Record<string, string | number>) =>
  i18n.translate(`observability.alerting.cloudwatch.form.${id}`, { defaultMessage, values });

/** The form's own state: strings where the user types, converted on save. */
interface FormState {
  alarmName: string;
  description: string;
  namespace: string;
  metricName: string;
  dimensions: Array<{ name: string; value: string }>;
  /** A statistic, or "percentile" to use `percentile`. */
  statistic: CloudWatchStatistic | 'percentile';
  percentile: string;
  period: string;
  evaluationPeriods: string;
  datapointsToAlarm: string;
  comparisonOperator: CloudWatchComparisonOperator;
  threshold: string;
  treatMissingData: CloudWatchTreatMissingData;
  actionsEnabled: boolean;
  alarmActions: string[];
  okActions: string[];
  tags: Array<{ key: string; value: string }>;
}

const DEFAULT_FORM: FormState = {
  alarmName: '',
  description: '',
  namespace: '',
  metricName: '',
  dimensions: [],
  statistic: 'Average',
  percentile: 'p99',
  period: '300',
  evaluationPeriods: '1',
  datapointsToAlarm: '',
  comparisonOperator: 'GreaterThanThreshold',
  threshold: '',
  treatMissingData: 'missing',
  actionsEnabled: true,
  alarmActions: [],
  okActions: [],
  tags: [],
};

function fromInput(input: CloudWatchMetricAlarmInput): FormState {
  return {
    ...DEFAULT_FORM,
    alarmName: input.alarmName,
    description: input.description ?? '',
    namespace: input.namespace,
    metricName: input.metricName,
    dimensions: (input.dimensions ?? []).map((d) => ({ ...d })),
    statistic: input.extendedStatistic ? 'percentile' : (input.statistic ?? 'Average'),
    percentile: input.extendedStatistic ?? 'p99',
    period: String(input.period),
    evaluationPeriods: String(input.evaluationPeriods),
    datapointsToAlarm: input.datapointsToAlarm ? String(input.datapointsToAlarm) : '',
    comparisonOperator: input.comparisonOperator,
    threshold: String(input.threshold),
    treatMissingData: input.treatMissingData ?? 'missing',
    actionsEnabled: input.actionsEnabled !== false,
    alarmActions: input.alarmActions ?? [],
    okActions: input.okActions ?? [],
  };
}

const toNumber = (value: string) => (value.trim() === '' ? NaN : Number(value));

/** Text typed into a combo box but not yet committed with Enter, by field. */
export type PendingText = Partial<
  Record<'namespace' | 'metricName' | 'alarmActions' | 'okActions', string>
>;

/**
 * The form with typed-but-uncommitted combo-box text applied. A combo box only takes typed text
 * on Enter, so without this a value typed and then left (or saved straight away) would be
 * dropped and the old one kept. Exported for tests.
 */
export function withPendingText(form: FormState, pending: PendingText): FormState {
  const next = { ...form };
  const ns = pending.namespace?.trim();
  if (ns) next.namespace = ns;
  const metric = pending.metricName?.trim();
  if (metric) next.metricName = metric;
  for (const field of ['alarmActions', 'okActions'] as const) {
    const arn = pending[field]?.trim();
    if (arn && !next[field].includes(arn)) next[field] = [...next[field], arn];
  }
  return next;
}

/** The write input for the form. Exported for tests. */
export function toInput(form: FormState, mode: 'create' | 'edit'): CloudWatchMetricAlarmInput {
  const input: CloudWatchMetricAlarmInput = {
    alarmName: form.alarmName.trim(),
    namespace: form.namespace.trim(),
    metricName: form.metricName.trim(),
    dimensions: form.dimensions.map((d) => ({ name: d.name.trim(), value: d.value })),
    period: toNumber(form.period),
    evaluationPeriods: toNumber(form.evaluationPeriods),
    comparisonOperator: form.comparisonOperator,
    threshold: toNumber(form.threshold),
    treatMissingData: form.treatMissingData,
    actionsEnabled: form.actionsEnabled,
    alarmActions: form.alarmActions,
    okActions: form.okActions,
  };
  if (form.description.trim()) input.description = form.description.trim();
  if (form.statistic === 'percentile') input.extendedStatistic = form.percentile.trim();
  else input.statistic = form.statistic;
  if (form.datapointsToAlarm.trim()) input.datapointsToAlarm = toNumber(form.datapointsToAlarm);
  // CloudWatch only applies tags when an alarm is created.
  if (mode === 'create' && form.tags.length > 0) input.tags = form.tags;
  return input;
}

const PERIOD_OPTIONS = [10, 30, 60, 300, 900, 3600, 21600, 86400].map((s) => ({
  value: String(s),
  text:
    s < 60
      ? t('periodSeconds', '{n} seconds', { n: s })
      : s < 3600
        ? t('periodMinutes', '{n} minutes', { n: s / 60 })
        : s < 86400
          ? t('periodHours', '{n} hours', { n: s / 3600 })
          : t('periodDay', '1 day'),
}));

const COMPARISON_OPTIONS: Array<{ value: CloudWatchComparisonOperator; text: string }> = [
  { value: 'GreaterThanThreshold', text: '>' },
  { value: 'GreaterThanOrEqualToThreshold', text: '>=' },
  { value: 'LessThanThreshold', text: '<' },
  { value: 'LessThanOrEqualToThreshold', text: '<=' },
];

const MISSING_DATA_OPTIONS: Array<{ value: CloudWatchTreatMissingData; text: string }> = [
  { value: 'missing', text: t('missing.missing', 'Treat as missing') },
  { value: 'notBreaching', text: t('missing.notBreaching', 'Treat as good (not breaching)') },
  { value: 'breaching', text: t('missing.breaching', 'Treat as bad (breaching)') },
  { value: 'ignore', text: t('missing.ignore', 'Ignore (keep the current state)') },
];

const STATISTIC_OPTIONS = [
  ...CLOUDWATCH_STATISTICS.map((s) => ({ value: s, text: s })),
  { value: 'percentile', text: t('percentileOption', 'Percentile') },
];

export interface CreateCloudWatchAlarmProps {
  dsId: string;
  /** Edit an existing alarm (seeded from its current settings); create otherwise. */
  initial?: CloudWatchMetricAlarmInput;
  /** Names already in the list, to warn before the server refuses a taken name. */
  existingNames?: string[];
  onClose: () => void;
  /** Called after the alarm was written. */
  onSaved: (alarmName: string, mode: 'create' | 'edit') => void;
}

export const CreateCloudWatchAlarm: React.FC<CreateCloudWatchAlarmProps> = ({
  dsId,
  initial,
  existingNames = [],
  onClose,
  onSaved,
}) => {
  const mode: 'create' | 'edit' = initial ? 'edit' : 'create';
  const [form, setForm] = useState<FormState>(() => (initial ? fromInput(initial) : DEFAULT_FORM));
  const [touched, setTouched] = useState(false);
  const [saving, setSaving] = useState(false);
  const [serverFieldError, setServerFieldError] = useState<{ field: string; message: string }>();
  const [serverError, setServerError] = useState<ClassifiedError | string>();
  const [metrics, setMetrics] = useState<CloudWatchMetricRef[]>([]);
  const [metricsUnavailable, setMetricsUnavailable] = useState(false);
  const [pending, setPending] = useState<PendingText>({});
  const typing = (field: keyof PendingText) => (value: string) =>
    setPending((prev) => ({ ...prev, [field]: value }));
  // Leaving a combo box keeps what was typed in it.
  const commitTyped = (field: keyof PendingText) => () => {
    setForm((prev) => withPendingText(prev, { [field]: pending[field] }));
    setPending((prev) => ({ ...prev, [field]: undefined }));
  };

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setServerFieldError(undefined);
  };

  // Metrics for the picker, by namespace. A failure leaves the fields free text.
  useEffect(() => {
    let cancelled = false;
    const handle = setTimeout(() => {
      listCloudWatchMetrics(dsId, { namespace: form.namespace.trim() || undefined })
        .then((list) => !cancelled && setMetrics(list.metrics))
        .catch(() => !cancelled && setMetricsUnavailable(true));
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [dsId, form.namespace]);

  // Typed text counts even before the combo box is left (e.g. Save clicked right away).
  const input = useMemo(() => toInput(withPendingText(form, pending), mode), [form, pending, mode]);
  const validation = useMemo(() => validateCloudWatchMetricAlarm(input), [input]);
  const nameTaken =
    mode === 'create' && existingNames.includes(input.alarmName) && input.alarmName !== '';

  const errorFor = (field: string): string | undefined => {
    if (serverFieldError?.field === field) return serverFieldError.message;
    if (!touched) return undefined;
    if (field === 'alarmName' && nameTaken) {
      return t('nameTaken', 'An alarm with this name already exists');
    }
    return validation.errors[field];
  };

  const namespaceOptions = useMemo(
    () =>
      Array.from(new Set(metrics.map((m) => m.namespace)))
        .sort()
        .map((label) => ({ label })),
    [metrics]
  );
  const metricOptions = useMemo(
    () =>
      Array.from(
        new Set(
          metrics
            .filter((m) => !form.namespace || m.namespace === form.namespace)
            .map((m) => m.metricName)
        )
      )
        .sort()
        .map((label) => ({ label })),
    [metrics, form.namespace]
  );
  // Picking a metric fills its first dimension set, which the user can change.
  const pickMetric = (metricName: string) => {
    const match = metrics.find(
      (m) => m.metricName === metricName && (!form.namespace || m.namespace === form.namespace)
    );
    setForm((prev) => ({
      ...prev,
      metricName,
      namespace: prev.namespace || match?.namespace || '',
      dimensions:
        prev.dimensions.length === 0 && match
          ? match.dimensions.map((d) => ({ ...d }))
          : prev.dimensions,
    }));
  };

  const save = async () => {
    setTouched(true);
    setServerError(undefined);
    setServerFieldError(undefined);
    // Keep the typed text in the form too, so it shows what was saved.
    setForm((prev) => withPendingText(prev, pending));
    setPending({});
    if (!validation.valid || nameTaken) return;
    setSaving(true);
    try {
      if (mode === 'create') await createCloudWatchAlarm(dsId, input);
      else await updateCloudWatchAlarm(dsId, input);
      onSaved(input.alarmName, mode);
    } catch (e: unknown) {
      const classified = extractClassifiedError(e);
      const body = (e as { body?: { message?: string; attributes?: { field?: string } } })?.body;
      if (classified) setServerError(classified);
      else if (body?.attributes?.field && body.message) {
        setServerFieldError({ field: body.attributes.field, message: body.message });
      } else {
        setServerError(body?.message || t('saveFailed', 'The alarm could not be saved.'));
      }
    } finally {
      setSaving(false);
    }
  };

  const actionsRow = (field: 'alarmActions' | 'okActions', label: string, help: string) => (
    <EuiFormRow
      label={label}
      helpText={help}
      isInvalid={!!errorFor(field)}
      error={errorFor(field)}
      fullWidth
    >
      <EuiComboBox
        isInvalid={!!errorFor(field)}
        noSuggestions
        fullWidth
        placeholder="arn:aws:sns:us-east-1:123456789012:my-topic"
        selectedOptions={form[field].map((arn) => ({ label: arn }))}
        onCreateOption={(value) => {
          const arn = value.trim();
          if (arn && !form[field].includes(arn)) set(field, [...form[field], arn]);
          setPending((prev) => ({ ...prev, [field]: undefined }));
        }}
        onSearchChange={typing(field)}
        onBlur={commitTyped(field)}
        onChange={(opts: Array<EuiComboBoxOptionOption<string>>) =>
          set(
            field,
            opts.map((o) => o.label)
          )
        }
        data-test-subj={`cloudWatchAlarm-${field}`}
      />
    </EuiFormRow>
  );

  return (
    <EuiFlyout onClose={onClose} size="m" ownFocus data-test-subj="createCloudWatchAlarmFlyout">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2>
            {mode === 'create'
              ? t('createTitle', 'Create CloudWatch alarm')
              : t('editTitle', 'Edit CloudWatch alarm')}
          </h2>
        </EuiTitle>
        <EuiText size="s" color="subdued">
          <p>
            {t(
              'subtitle',
              'A metric alarm with a static threshold, in this account and Region. Changes are made in CloudWatch with your own AWS permissions.'
            )}
          </p>
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {serverError && (
          <>
            {typeof serverError === 'string' ? (
              <EuiCallOut color="danger" iconType="alert" title={serverError} />
            ) : (
              <ClassifiedErrorCallout error={serverError} />
            )}
            <EuiSpacer size="m" />
          </>
        )}
        {mode === 'edit' && (
          <>
            <EuiCallOut
              size="s"
              iconType="iInCircle"
              title={t(
                'editNote',
                'Saving replaces the alarm in CloudWatch. If it is managed by CloudFormation or Terraform, change it there instead, or the next deployment will undo this edit.'
              )}
            />
            <EuiSpacer size="m" />
          </>
        )}
        <EuiForm component="form" onSubmit={(e: React.FormEvent) => e.preventDefault()}>
          <EuiTitle size="xs">
            <h3>{t('detailsSection', 'Details')}</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiFormRow
            label={t('name', 'Alarm name')}
            isInvalid={!!errorFor('alarmName')}
            error={errorFor('alarmName')}
            helpText={
              mode === 'edit' ? t('nameFixed', "An alarm's name can't be changed.") : undefined
            }
            fullWidth
          >
            <EuiFieldText
              isInvalid={!!errorFor('alarmName')}
              fullWidth
              value={form.alarmName}
              disabled={mode === 'edit'}
              onChange={(e) => set('alarmName', e.target.value)}
              data-test-subj="cloudWatchAlarm-alarmName"
            />
          </EuiFormRow>
          <EuiFormRow
            label={t('description', 'Description (optional)')}
            isInvalid={!!errorFor('description')}
            error={errorFor('description')}
            fullWidth
          >
            <EuiTextArea
              isInvalid={!!errorFor('description')}
              fullWidth
              rows={2}
              value={form.description}
              onChange={(e) => set('description', e.target.value)}
            />
          </EuiFormRow>

          <EuiSpacer size="l" />
          <EuiTitle size="xs">
            <h3>{t('metricSection', 'Metric')}</h3>
          </EuiTitle>
          {metricsUnavailable && (
            <EuiText size="xs" color="subdued">
              <p>
                {t(
                  'metricsUnavailable',
                  "Metrics couldn't be listed; type the namespace and metric name."
                )}
              </p>
            </EuiText>
          )}
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="m">
            <EuiFlexItem>
              <EuiFormRow
                label={t('namespace', 'Namespace')}
                isInvalid={!!errorFor('namespace')}
                error={errorFor('namespace')}
              >
                <EuiComboBox
                  isInvalid={!!errorFor('namespace')}
                  singleSelection={{ asPlainText: true }}
                  placeholder="AWS/EC2"
                  options={namespaceOptions}
                  selectedOptions={form.namespace ? [{ label: form.namespace }] : []}
                  onCreateOption={(v) => {
                    set('namespace', v.trim());
                    setPending((prev) => ({ ...prev, namespace: undefined }));
                  }}
                  onChange={(opts) => set('namespace', opts[0]?.label ?? '')}
                  onSearchChange={typing('namespace')}
                  onBlur={commitTyped('namespace')}
                  data-test-subj="cloudWatchAlarm-namespace"
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow
                label={t('metricName', 'Metric name')}
                isInvalid={!!errorFor('metricName')}
                error={errorFor('metricName')}
              >
                <EuiComboBox
                  isInvalid={!!errorFor('metricName')}
                  singleSelection={{ asPlainText: true }}
                  placeholder="CPUUtilization"
                  options={metricOptions}
                  selectedOptions={form.metricName ? [{ label: form.metricName }] : []}
                  onCreateOption={(v) => {
                    set('metricName', v.trim());
                    setPending((prev) => ({ ...prev, metricName: undefined }));
                  }}
                  onChange={(opts) => (opts[0] ? pickMetric(opts[0].label) : set('metricName', ''))}
                  onSearchChange={typing('metricName')}
                  onBlur={commitTyped('metricName')}
                  data-test-subj="cloudWatchAlarm-metricName"
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiFormRow
            label={t('dimensions', 'Dimensions')}
            isInvalid={!!errorFor('dimensions')}
            error={errorFor('dimensions')}
            fullWidth
          >
            <div>
              {form.dimensions.map((d, i) => (
                <EuiFlexGroup key={i} gutterSize="s" alignItems="center" responsive={false}>
                  <EuiFlexItem>
                    <EuiFieldText
                      compressed
                      placeholder={t('dimensionName', 'Name')}
                      value={d.name}
                      isInvalid={!!errorFor(`dimensions.${i}.name`)}
                      onChange={(e) =>
                        set(
                          'dimensions',
                          form.dimensions.map((x, j) =>
                            j === i ? { ...x, name: e.target.value } : x
                          )
                        )
                      }
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFieldText
                      compressed
                      placeholder={t('dimensionValue', 'Value')}
                      value={d.value}
                      isInvalid={!!errorFor(`dimensions.${i}.value`)}
                      onChange={(e) =>
                        set(
                          'dimensions',
                          form.dimensions.map((x, j) =>
                            j === i ? { ...x, value: e.target.value } : x
                          )
                        )
                      }
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="trash"
                      color="danger"
                      aria-label={t('removeDimension', 'Remove dimension')}
                      onClick={() =>
                        set(
                          'dimensions',
                          form.dimensions.filter((_, j) => j !== i)
                        )
                      }
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              ))}
              <EuiButtonEmpty
                size="xs"
                iconType="plusInCircle"
                onClick={() => set('dimensions', [...form.dimensions, { name: '', value: '' }])}
              >
                {t('addDimension', 'Add dimension')}
              </EuiButtonEmpty>
            </div>
          </EuiFormRow>
          <EuiFlexGroup gutterSize="m">
            <EuiFlexItem>
              <EuiFormRow
                label={t('statistic', 'Statistic')}
                isInvalid={!!errorFor('statistic')}
                error={errorFor('statistic')}
              >
                <EuiSelect
                  isInvalid={!!errorFor('statistic')}
                  options={STATISTIC_OPTIONS}
                  value={form.statistic}
                  onChange={(e) => set('statistic', e.target.value as FormState['statistic'])}
                  data-test-subj="cloudWatchAlarm-statistic"
                />
              </EuiFormRow>
            </EuiFlexItem>
            {form.statistic === 'percentile' && (
              <EuiFlexItem>
                <EuiFormRow
                  label={t('percentile', 'Percentile')}
                  isInvalid={!!errorFor('extendedStatistic')}
                  error={errorFor('extendedStatistic')}
                >
                  <EuiFieldText
                    isInvalid={!!errorFor('extendedStatistic')}
                    value={form.percentile}
                    onChange={(e) => set('percentile', e.target.value)}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            )}
            <EuiFlexItem>
              <EuiFormRow
                label={t('period', 'Period')}
                isInvalid={!!errorFor('period')}
                error={errorFor('period')}
              >
                <EuiSelect
                  isInvalid={!!errorFor('period')}
                  options={
                    PERIOD_OPTIONS.some((o) => o.value === form.period)
                      ? PERIOD_OPTIONS
                      : [...PERIOD_OPTIONS, { value: form.period, text: `${form.period}s` }]
                  }
                  value={form.period}
                  onChange={(e) => set('period', e.target.value)}
                  data-test-subj="cloudWatchAlarm-period"
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="l" />
          <EuiTitle size="xs">
            <h3>{t('conditionSection', 'Condition')}</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="m">
            <EuiFlexItem grow={false} style={{ minWidth: 100 }}>
              <EuiFormRow
                label={t('comparison', 'Is')}
                isInvalid={!!errorFor('comparisonOperator')}
              >
                <EuiSelect
                  isInvalid={!!errorFor('comparisonOperator')}
                  options={COMPARISON_OPTIONS}
                  value={form.comparisonOperator}
                  onChange={(e) =>
                    set('comparisonOperator', e.target.value as CloudWatchComparisonOperator)
                  }
                  data-test-subj="cloudWatchAlarm-comparison"
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow
                label={t('threshold', 'Threshold')}
                isInvalid={!!errorFor('threshold')}
                error={errorFor('threshold')}
              >
                <EuiFieldNumber
                  isInvalid={!!errorFor('threshold')}
                  value={form.threshold}
                  onChange={(e) => set('threshold', e.target.value)}
                  data-test-subj="cloudWatchAlarm-threshold"
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiFlexGroup gutterSize="m">
            <EuiFlexItem>
              <EuiFormRow
                label={t('datapointsToAlarm', 'Datapoints to alarm (optional)')}
                helpText={t('datapointsHelp', 'M of N. Empty means all of them.')}
                isInvalid={!!errorFor('datapointsToAlarm')}
                error={errorFor('datapointsToAlarm')}
              >
                <EuiFieldNumber
                  isInvalid={!!errorFor('datapointsToAlarm')}
                  min={1}
                  value={form.datapointsToAlarm}
                  onChange={(e) => set('datapointsToAlarm', e.target.value)}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow
                label={t('evaluationPeriods', 'Out of evaluation periods')}
                isInvalid={!!errorFor('evaluationPeriods')}
                error={errorFor('evaluationPeriods')}
              >
                <EuiFieldNumber
                  isInvalid={!!errorFor('evaluationPeriods')}
                  min={1}
                  value={form.evaluationPeriods}
                  onChange={(e) => set('evaluationPeriods', e.target.value)}
                  data-test-subj="cloudWatchAlarm-evaluationPeriods"
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiFormRow label={t('missingData', 'Missing data')} fullWidth>
            <EuiSelect
              fullWidth
              options={MISSING_DATA_OPTIONS}
              value={form.treatMissingData}
              onChange={(e) =>
                set('treatMissingData', e.target.value as CloudWatchTreatMissingData)
              }
            />
          </EuiFormRow>

          <EuiSpacer size="l" />
          <EuiTitle size="xs">
            <h3>{t('notificationsSection', 'Notifications')}</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          {actionsRow(
            'alarmActions',
            t('alarmActions', 'When in ALARM, notify'),
            t('actionsHelp', 'Amazon SNS topic ARNs, up to 5. Press Enter after each.')
          )}
          {actionsRow(
            'okActions',
            t('okActions', 'When back to OK, notify'),
            t('actionsHelp', 'Amazon SNS topic ARNs, up to 5. Press Enter after each.')
          )}
          <EuiFormRow fullWidth>
            <EuiSwitch
              label={t('actionsEnabled', 'Send notifications')}
              checked={form.actionsEnabled}
              onChange={(e) => set('actionsEnabled', e.target.checked)}
            />
          </EuiFormRow>

          {mode === 'create' && (
            <>
              <EuiSpacer size="l" />
              <EuiTitle size="xs">
                <h3>{t('tagsSection', 'Tags (optional)')}</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {form.tags.map((tag, i) => (
                <EuiFlexGroup key={i} gutterSize="s" alignItems="center" responsive={false}>
                  <EuiFlexItem>
                    <EuiFieldText
                      compressed
                      placeholder={t('tagKey', 'Key')}
                      value={tag.key}
                      isInvalid={!!errorFor(`tags.${i}.key`)}
                      onChange={(e) =>
                        set(
                          'tags',
                          form.tags.map((x, j) => (j === i ? { ...x, key: e.target.value } : x))
                        )
                      }
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFieldText
                      compressed
                      placeholder={t('tagValue', 'Value')}
                      value={tag.value}
                      onChange={(e) =>
                        set(
                          'tags',
                          form.tags.map((x, j) => (j === i ? { ...x, value: e.target.value } : x))
                        )
                      }
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="trash"
                      color="danger"
                      aria-label={t('removeTag', 'Remove tag')}
                      onClick={() =>
                        set(
                          'tags',
                          form.tags.filter((_, j) => j !== i)
                        )
                      }
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              ))}
              <EuiButtonEmpty
                size="xs"
                iconType="plusInCircle"
                onClick={() => set('tags', [...form.tags, { key: '', value: '' }])}
              >
                {t('addTag', 'Add tag')}
              </EuiButtonEmpty>
            </>
          )}
        </EuiForm>
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent="spaceBetween">
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose}>{t('cancel', 'Cancel')}</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              isLoading={saving}
              onClick={save}
              isDisabled={touched && (!validation.valid || nameTaken)}
              data-test-subj="cloudWatchAlarm-save"
            >
              {mode === 'create' ? t('create', 'Create alarm') : t('save', 'Save changes')}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
