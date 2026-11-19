
import type {
  IndicatorDetailResponse,
  IndicatorObservation,
} from '../../types/indicatorDetail'

interface IndicatorInvestigationPanelProps {
  indicatorId: number
  data: IndicatorDetailResponse | null
  loading: boolean
  error: string | null
  onClose: () => void
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'NOT AVAILABLE'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return 'INVALID TIMESTAMP'
  }

  return date.toLocaleString()
}

function displayValue(
  value: string | null | undefined,
): string {
  return value && value.trim()
    ? value
    : 'NOT REPORTED'
}

function getTags(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }

  return value.filter(
    (item): item is string =>
      typeof item === 'string',
  )
}

function MetadataField({
  label,
  value,
}: {
  label: string
  value: string | number
}) {
  return (
    <div className="min-w-0 space-y-1.5">
      <dt className="font-mono text-[10px] tracking-wider text-[#779F8E]">
        {label}
      </dt>

      <dd className="break-words font-mono text-[11px] leading-5 text-[#C8E9D9]">
        {value}
      </dd>
    </div>
  )
}

function ObservationCard({
  observation,
}: {
  observation: IndicatorObservation
}) {
  const tags = getTags(observation.tags)

  const timestampWarning =
    observation.timestampQuality !== 'consistent'

  return (
    <article className="overflow-hidden rounded border border-[#2D5145] bg-[#0D191A]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#29483E] bg-[#11241F] px-4 py-3">
        <div className="min-w-0">
          <p className="font-mono text-[10px] tracking-wider text-[#77B69D]">
            INTELLIGENCE SOURCE
          </p>

          <h4 className="mt-1 text-sm font-semibold text-[#BDF5D9]">
            {observation.sourceName}
          </h4>
        </div>

        <div className="rounded border border-[#376E57] bg-[#153326] px-3 py-2 text-right">
          <p className="font-mono text-[9px] text-[#8DC9AD]">
            SOURCE CONFIDENCE
          </p>

          <p className="mt-1 font-mono text-lg font-semibold tabular-nums text-[#76E8B5]">
            {observation.confidenceLevel}/100
          </p>
        </div>
      </div>

      <dl className="grid gap-5 p-4 sm:grid-cols-2">
        <MetadataField
          label="SOURCE RECORD"
          value={observation.sourceRecordId}
        />

        <MetadataField
          label="THREAT TYPE"
          value={observation.threatType}
        />

        <MetadataField
          label="MALWARE FAMILY"
          value={displayValue(
            observation.malwareFamily,
          )}
        />

        <MetadataField
          label="REPORTER"
          value={displayValue(
            observation.reporter,
          )}
        />

        <MetadataField
          label="FIRST SEEN"
          value={formatDate(
            observation.firstSeenUtc,
          )}
        />

        <MetadataField
          label="LAST SEEN"
          value={formatDate(
            observation.lastSeenUtc,
          )}
        />

        <MetadataField
          label="LAST UPDATED"
          value={formatDate(
            observation.updatedAtUtc,
          )}
        />

        <MetadataField
          label="TIMESTAMP QUALITY"
          value={observation.timestampQuality}
        />
      </dl>

      {timestampWarning && (
        <div
          role="note"
          className="mx-4 mb-4 rounded border border-[#795B37] bg-[#2A2117] px-3 py-2 font-mono text-[10px] leading-5 text-[#E9C18A]"
        >
          TIMESTAMP WARNING: The source observation
          reports {observation.timestampQuality}.
          Review the recorded timestamps before
          interpreting the observation interval.
        </div>
      )}

      <div className="space-y-4 border-t border-[#29483E] px-4 py-4">
        <div>
          <p className="font-mono text-[10px] tracking-wider text-[#779F8E]">
            SOURCE REFERENCE
          </p>

          <p className="tf-ioc-value mt-2 text-[11px] leading-5 text-[#B5DCCB]">
            {displayValue(observation.reference)}
          </p>
        </div>

        <div>
          <p className="font-mono text-[10px] tracking-wider text-[#779F8E]">
            INTELLIGENCE TAGS
          </p>

          {tags.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-2">
              {tags.map((tag, index) => (
                <span
                  key={`${index}-${tag}`}
                  className="max-w-full break-all rounded border border-[#315B4D] bg-[#142A22] px-2 py-1 font-mono text-[10px] text-[#A0E4C3]"
                >
                  {tag}
                </span>
              ))}
            </div>
          ) : (
            <p className="mt-2 font-mono text-[11px] text-[#779F8E]">
              NO TAGS REPORTED
            </p>
          )}
        </div>
      </div>
    </article>
  )
}

export function IndicatorInvestigationPanel({
  indicatorId,
  data,
  loading,
  error,
  onClose,
}: IndicatorInvestigationPanelProps) {
  return (
    <section
      aria-labelledby="investigation-heading"
      aria-busy={loading}
      className="tf-glow-border overflow-hidden rounded border border-[#32715B] bg-[#101A1D]"
    >
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#31594B] bg-[#0D201B] px-5 py-4">
        <div>
          <p className="font-mono text-[10px] tracking-wider text-[#78BE9F]">
            // IOC INVESTIGATION
          </p>

          <h2
            id="investigation-heading"
            className="mt-2 text-lg font-semibold text-[#E1FCEC]"
          >
            Indicator Investigation
          </h2>

          <p className="mt-1 font-mono text-[11px] text-[#8EB6A4]">
            CANONICAL IOC ID #{indicatorId}
          </p>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="rounded border border-[#37614E] bg-[#153025] px-3 py-2 font-mono text-[10px] text-[#ADE9CA] transition-colors hover:border-[#70E3B4] hover:bg-[#1F4533]"
        >
          CLOSE
        </button>
      </div>

      {loading && (
        <div
          role="status"
          className="flex min-h-[180px] items-center justify-center gap-3"
        >
          <span
            aria-hidden="true"
            className="h-5 w-5 animate-spin rounded-full border-2 border-[#31594C] border-t-[#51E9B5]"
          />

          <span className="font-mono text-xs text-[#A0DAC0]">
            RETRIEVING SOURCE INTELLIGENCE...
          </span>
        </div>
      )}

      {!loading && error && (
        <div
          role="alert"
          className="m-5 rounded border border-[#794447] bg-[#2A191C] px-4 py-3"
        >
          <p className="font-mono text-xs font-semibold text-[#FFAAAA]">
            INVESTIGATION REQUEST FAILED
          </p>

          <p className="mt-2 text-xs text-[#E8B1B3]">
            {error}
          </p>
        </div>
      )}

      {!loading && !error && data && (
        <div className="space-y-5 p-5">
          <div className="rounded border border-[#31594B] bg-[#0B1917] p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="font-mono text-[10px] tracking-wider text-[#82B5A0]">
                NORMALIZED INDICATOR VALUE
              </span>

              <span className="rounded border border-[#34765E] bg-[#123226] px-2.5 py-1 font-mono text-[10px] text-[#9BECC5]">
                {data.indicatorType}
              </span>
            </div>

            <p className="tf-ioc-value mt-3 text-[13px] leading-6 text-[#D7FFEC]">
              {data.normalizedValue}
            </p>

            <p className="mt-3 font-mono text-[10px] text-[#7CA491]">
              FIRST STORED: {formatDate(data.createdAtUtc)}
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#29483E] pb-3">
            <div>
              <h3 className="text-sm font-semibold text-[#D9F5E6]">
                Current source observations
              </h3>

              <p className="mt-1 text-xs text-[#87AE9B]">
                Source-reported intelligence, not an
                independently calculated risk score
              </p>
            </div>

            <span className="font-mono text-xl font-semibold tabular-nums text-[#6AE7B5]">
              {data.observationCount.toLocaleString()}
            </span>
          </div>

          {data.observations.length === 0 ? (
            <div className="rounded border border-[#2B4D41] px-4 py-8 text-center font-mono text-xs text-[#8DB6A2]">
              NO CURRENT SOURCE OBSERVATIONS FOUND
            </div>
          ) : (
            <div className="grid gap-4 xl:grid-cols-2">
              {data.observations.map((observation) => (
                <ObservationCard
                  key={observation.id}
                  observation={observation}
                />
              ))}
            </div>
          )}

          {data.hasMoreObservations && (
            <div
              role="note"
              className="rounded border border-[#795B37] bg-[#2A2117] px-4 py-3 font-mono text-[10px] text-[#E9C18A]"
            >
              ADDITIONAL OBSERVATIONS EXIST.
              This API response contains only the
              first 100 current observation records.
            </div>
          )}

          <p className="border-t border-[#29483E] pt-4 font-mono text-[10px] leading-5 text-[#769B8A]">
            INVESTIGATION NOTE — IOC values and source
            references are displayed as inert text.
            Confidence and threat classifications are
            source-reported. This view does not establish
            confirmed compromise or incident severity.
          </p>
        </div>
      )}
    </section>
  )
}
