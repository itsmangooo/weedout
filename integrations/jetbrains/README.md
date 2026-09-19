# Weedout for JetBrains IDEs

The plugin starts with the project, watches supported dependency files and
`.weedout.yml`, and automatically updates editor warnings, inline fix hints,
hover details, and the native Weedout findings tool window.

It intentionally exposes only Auth, Rules, Create Project, and Delete Project.
Normal scanning has no command because it follows project changes automatically.
