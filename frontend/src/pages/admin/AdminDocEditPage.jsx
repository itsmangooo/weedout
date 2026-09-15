import { PageFrame } from "../../components/ui/PageFrame";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { createDocPage, updateDocPage } from "../../api/admin";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { useAdminMutation, useDocPage } from "../../features/admin/hooks/useAdmin";

const BLANK = { title: "", slug: "", summary: "", content: "", published: false, position: 0 };

export function AdminDocEditPage() {
  const { pageId } = useParams();
  const query = useDocPage(pageId);

  if (pageId && query.isPending) return <AsyncLoading>Reading the page…</AsyncLoading>;
  if (pageId && query.isError) {
    return <AsyncError error={query.error} onRetry={() => query.refetch()} />;
  }

  // Keyed on the record so switching pages remounts the form rather than
  // leaving one page's draft in the fields of another.
  return <DocEditor key={pageId ?? "new"} page={pageId ? query.data : null} />;
}

function DocEditor({ page }) {
  const navigate = useNavigate();
  const [fields, setFields] = useState(page ? { ...BLANK, ...page } : BLANK);

  const save = useAdminMutation(
    () => {
      const payload = {
        title: fields.title,
        slug: fields.slug,
        summary: fields.summary,
        content: fields.content,
        published: fields.published,
        position: Number(fields.position) || 0,
      };
      return page ? updateDocPage(page.id, payload) : createDocPage(payload);
    },
    { onSuccess: () => navigate("/admin/docs") },
  );

  function set(name, value) {
    setFields((current) => ({ ...current, [name]: value }));
  }

  return (
    <PageFrame className="operations-page operations-docedit" eyebrow="Weedout / Operations" title={page ? "Edit page" : "New page"} description="Edit the source and publication details." actions={<><div className="btn-row">
          {page?.published ? (
            <a
              className="button button--ghost"
              href={`/docs/${page.slug}`}
              rel="noopener"
              target="_blank"
            >
              View live
            </a>
          ) : null}
          <Link className="button button--ghost" to="/admin/docs">
            Back to docs
          </Link>
        </div></>}>

      {save.isError ? (
        <div className="u-mb-5">
          <InlineNotice tone="danger">{save.error.message}</InlineNotice>
        </div>
      ) : null}

      <form
        className="doc-editor"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="doc-editor__meta">
          <div className="field">
            <label htmlFor="title">Title</label>
            <input
              className="input"
              id="title"
              maxLength={200}
              onChange={(event) => set("title", event.target.value)}
              required
              type="text"
              value={fields.title}
            />
          </div>

          <div className="field">
            <label htmlFor="slug">Slug</label>
            <input
              className="input mono"
              id="slug"
              maxLength={120}
              onChange={(event) => set("slug", event.target.value)}
              placeholder="derived from the title"
              type="text"
              value={fields.slug}
            />
            <p className="field__hint">
              The URL is <code>/docs/&lt;slug&gt;</code>.
            </p>
          </div>

          <div className="field">
            <label htmlFor="position">Order</label>
            <input
              className="input"
              id="position"
              max={10000}
              min={0}
              onChange={(event) => set("position", event.target.value)}
              type="number"
              value={fields.position}
            />
            <p className="field__hint">Lowest first on the index.</p>
          </div>

          <div className="checkbox-row">
            <input
              checked={fields.published}
              id="published"
              onChange={(event) => set("published", event.target.checked)}
              type="checkbox"
            />
            <div>
              <label className="label" htmlFor="published">
                Published
              </label>
              <p className="field__hint u-flush">
                Drafts are invisible to everyone — <code>/docs/&lt;slug&gt;</code> returns 404.
              </p>
            </div>
          </div>
        </div>

        <div className="field">
          <label htmlFor="summary">Summary</label>
          <input
            className="input"
            id="summary"
            maxLength={300}
            onChange={(event) => set("summary", event.target.value)}
            placeholder="One line, shown on the index and in search results"
            type="text"
            value={fields.summary}
          />
          <p className="field__hint">Leave blank to derive it from the first paragraph.</p>
        </div>

        <div className="field">
          <div className="label-row">
            <label htmlFor="content">Content</label>
            <span className="label-row__aside mono">Markdown</span>
          </div>
          {/* No live preview here, deliberately. The rendered editor had one
              built from a small Markdown subset, which meant the thing on
              screen was never quite the thing that shipped. The published page
              is rendered by the real parser; "View live" shows that, and an
              approximation that disagrees with it is worse than none. */}
          <textarea
            className="textarea doc-editor__source"
            id="content"
            onChange={(event) => set("content", event.target.value)}
            placeholder={"# Heading\n\nBody text…"}
            rows={24}
            spellCheck={false}
            value={fields.content}
          />
        </div>

        <div className="btn-row">
          <Button disabled={save.isPending} type="submit">
            {save.isPending ? "Saving…" : page ? "Save changes" : "Create page"}
          </Button>
          <Link className="button button--ghost" to="/admin/docs">
            Cancel
          </Link>
        </div>
      </form>
    </PageFrame>
  );
}
