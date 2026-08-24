import { useLandingData } from "../hooks/useLandingData";

/**
 * Companies that asked to be named here.
 *
 * Every name on this list is there because that company ticked a box, and
 * because somebody here then checked the name was theirs to give. Both, and
 * the server enforces both — this component renders what it is handed and has
 * no opinion about who qualifies.
 *
 * It disappears when there is nobody to name, for the same reason `LiveSignal`
 * does: an empty trust section is worse than no trust section, and a padded
 * one is a lie on the page that is meant to be the honest part. Three names
 * that are real beat twenty that are decoration.
 *
 * Names only — no logos. A logo wall means chasing SVGs, hosting somebody's
 * trademark, and getting the rendering of it wrong on a dark background. The
 * name is the claim; the artwork is not.
 */
export function UsedBy() {
  const { data } = useLandingData();
  const companies = data?.used_by ?? [];

  if (companies.length === 0) {
    return null;
  }

  return (
    <section aria-labelledby="used-by-title" className="used-by">
      <h2 className="section-label" id="used-by-title">
        Watching dependencies at
      </h2>
      <ul className="used-by__list">
        {companies.map((company) => (
          <li key={company.name}>
            {company.website ? (
              <a href={company.website} rel="noopener noreferrer nofollow" target="_blank">
                {company.name}
              </a>
            ) : (
              <span>{company.name}</span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
