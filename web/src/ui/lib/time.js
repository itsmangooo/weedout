/**
 * Relative time, in the reader's own locale.
 *
 * Extracted from ProjectRow, which had the only copy until the project page
 * needed the same thing. Two copies of a formatter is how "3 days ago" and
 * "3 days" end up on the same screen.
 */
export function relativeTime(value) {
  if (!value) return null;

  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return null;

  const seconds = Math.round((timestamp - Date.now()) / 1_000);
  const ranges = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [30, "day"],
    [12, "month"],
    [Number.POSITIVE_INFINITY, "year"],
  ];

  let valueInUnit = seconds;
  for (const [size, unit] of ranges) {
    if (Math.abs(valueInUnit) < size) {
      return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(valueInUnit, unit);
    }
    valueInUnit = Math.round(valueInUnit / size);
  }
  return null;
}

/**
 * When the next check is due.
 *
 * Separate from relativeTime because a scheduled time that has already passed
 * is not "8 hours ago" — that reads as a check that happened. It means the
 * check is late, and a project whose scans have quietly stopped otherwise
 * looks identical to one with nothing to report.
 */
export function dueTime(value) {
  if (!value) return null;

  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return null;

  if (timestamp <= Date.now()) {
    return "overdue";
  }
  return relativeTime(value);
}
