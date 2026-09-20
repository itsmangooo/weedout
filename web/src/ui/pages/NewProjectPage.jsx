import { FileArrowUp as FileUp } from "@phosphor-icons/react/FileArrowUp";
import { ClipboardText as ClipboardPaste } from "@phosphor-icons/react/ClipboardText";
import { Terminal } from "@phosphor-icons/react/Terminal";
import { useState } from "react";
import { useNavigate } from "react-router";

import { ApiError } from "../api/client";
import { createProject } from "../api/projects";
import { Button } from "../components/ui/Button";
import { InlineNotice } from "../components/ui/InlineNotice";

/**
 * Three ways to start a project, on one screen.
 *
 * Upload a lockfile, paste one, or neither — a name and an ecosystem, so a key
 * can be scoped to it and CI can push the first scan. The third is the common
 * path for anyone using the CLI, and it is not hidden behind the other two.
 */

const METHODS = [
  { id: "upload", icon: FileUp, label: "Upload a file", hint: "package-lock.json, requirements.txt, go.sum" },
  { id: "paste", icon: ClipboardPaste, label: "Paste it", hint: "when the file is on another machine" },
  { id: "empty", icon: Terminal, label: "Start empty", hint: "push the first scan from CI" },
];

const ECOSYSTEMS = [
  { value: "npm", label: "npm" },
  { value: "PyPI", label: "PyPI" },
  { value: "Go", label: "Go" },
];

export function NewProjectPage() {
  const navigate = useNavigate();

  const [method, setMethod] = useState("upload");
  const [name, setName] = useState("");
  const [ecosystem, setEcosystem] = useState("npm");
  const [file, setFile] = useState(null);
  const [content, setContent] = useState("");
  const [filename, setFilename] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const created = await createProject({
        name,
        ecosystem: method === "empty" ? ecosystem : undefined,
        file: method === "upload" ? file : undefined,
        content: method === "paste" ? content : undefined,
        filename: method === "paste" ? filename : undefined,
      });
      navigate(`/targets/${created.id}`);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Could not create that project. Try again.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="project-create page-frame">
      <header className="page-head">
        <p className="section-label">New project</p>
        <h1>Watch a project</h1>
        <p className="page-head__lede">
          Start with a manifest. Weedout matches known vulnerabilities and adds the dependency context to help you decide what needs attention.
        </p>
      </header>

      {error ? (
        <div className="u-mb-5">
          <InlineNotice tone="danger">{error}</InlineNotice>
        </div>
      ) : null}

      <form className="stack-form" noValidate onSubmit={onSubmit}>
        <fieldset className="method-picker">
          <legend className="auth-field__label">How would you like to start?</legend>
          <div className="method-picker__options">
            {METHODS.map((option) => {
              const Icon = option.icon;
              const selected = method === option.id;
              return (
                <label
                  className={`method-option${selected ? " method-option--selected" : ""}`}
                  key={option.id}
                >
                  <input
                    checked={selected}
                    name="method"
                    onChange={() => setMethod(option.id)}
                    type="radio"
                    value={option.id}
                  />
                  <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
                  <span className="method-option__label">{option.label}</span>
                  <span className="method-option__hint">{option.hint}</span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <div className="auth-field">
          <label className="auth-field__label" htmlFor="name">
            Project name {method !== "empty" ? <span className="dim">(optional)</span> : null}
          </label>
          <input
            className="auth-field__input"
            id="name"
            name="name"
            onChange={(event) => setName(event.target.value)}
            placeholder="acme-storefront"
            required={method === "empty"}
            type="text"
            value={name}
          />
          {method !== "empty" ? (
            <p className="auth-field__hint">Taken from the filename if you leave it blank.</p>
          ) : null}
        </div>

        {method === "upload" ? (
          <div className="auth-field">
            <label className="auth-field__label" htmlFor="manifest">
              Manifest file
            </label>
            <input
              accept=".json,.txt,.lock,.sum,.toml,.yaml,.yml"
              className="auth-field__input"
              id="manifest"
              name="manifest"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              required
              type="file"
            />
            <p className="auth-field__hint">
              A lockfile gives the best answer, because it pins exact versions.
            </p>
          </div>
        ) : null}

        {method === "paste" ? (
          <>
            <div className="auth-field">
              <label className="auth-field__label" htmlFor="filename">
                File name
              </label>
              <input
                className="auth-field__input"
                id="filename"
                name="filename"
                onChange={(event) => setFilename(event.target.value)}
                placeholder="package-lock.json"
                required
                type="text"
                value={filename}
              />
              <p className="auth-field__hint">
                How we know which format it is. The name matters, the path does not.
              </p>
            </div>
            <div className="auth-field">
              <label className="auth-field__label" htmlFor="content">
                Contents
              </label>
              <textarea
                className="auth-field__input auth-field__input--area"
                id="content"
                name="content"
                onChange={(event) => setContent(event.target.value)}
                required
                rows={12}
                value={content}
              />
            </div>
          </>
        ) : null}

        {method === "empty" ? (
          <div className="auth-field">
            <label className="auth-field__label" htmlFor="ecosystem">
              Ecosystem
            </label>
            <select
              className="auth-field__input"
              id="ecosystem"
              name="ecosystem"
              onChange={(event) => setEcosystem(event.target.value)}
              value={ecosystem}
            >
              {ECOSYSTEMS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <p className="auth-field__hint">
              The project starts empty. Create a key on the project page and run{" "}
              <code>weedout scan --ci</code> in your pipeline.
            </p>
          </div>
        ) : null}

        <div className="auth-actions">
          <Button disabled={busy} type="submit">
            {busy ? "Creating…" : "Create project"}
          </Button>
        </div>
      </form>
    </div>
  );
}
