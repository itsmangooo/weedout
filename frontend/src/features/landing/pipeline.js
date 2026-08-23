/**
 * The particles for the landing's CLI section.
 *
 * Fixed rather than random. A `Math.random()` here would give every render a
 * different picture — different between the test and the page, and different
 * between two people looking at the same screenshot — and the counts below are
 * quoted in the copy beside it, so they have to be facts rather than a seed.
 *
 * `lane` is a row, `offset` staggers the start so the stream does not pulse in
 * columns, and `speed` varies the drift so it reads as flow rather than as a
 * marching grid.
 */

const LANES = 7;

/** A small deterministic spread — enough irregularity to look unplanned. */
function scatter(index, salt) {
  return ((index * 37 + salt * 11) % 29) / 29;
}

export const PARTICLES = Array.from({ length: 34 }, (_, index) => ({
  id: index,
  lane: index % LANES,
  offset: scatter(index, 3),
  speed: 0.82 + scatter(index, 7) * 0.5,
  size: index % 5 === 0 ? 5 : 3,
}));

/**
 * The one that gets through.
 *
 * Index rather than a flag on the particle, so the copy and the graphic cannot
 * disagree about how many survive: the section says "one", and this is it.
 */
export const SURVIVOR_ID = 18;

export const LANE_COUNT = LANES;

/** What the section claims, in one place so the graphic and the prose agree. */
export const PIPELINE_FACTS = {
  scanned: 1284,
  advisories: 47,
  reachable: 3,
  exploited: 1,
};
