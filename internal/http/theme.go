package bridgehttp

import "net/http"

const themeScript = `(() => {
  const storageKey = "indieauth-bridge-theme";
  const choices = ["system", "light", "dark"];
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";

  try {
    const saved = window.localStorage.getItem(storageKey);
    if (choices.includes(saved)) preference = saved;
  } catch (_) {}

  function applyTheme() {
    const resolved = preference === "system"
      ? (media.matches ? "dark" : "light")
      : preference;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.dataset.themePreference = preference;
    document.querySelectorAll(".iab-theme-choice").forEach((button) => {
      const selected = button.dataset.themeChoice === preference;
      button.setAttribute("aria-pressed", String(selected));
    });
  }

  applyTheme();

  const style = document.createElement("style");
  style.textContent = ` + "`" + `
    html[data-theme="dark"] {
      color-scheme: dark;
      --bg: #080c14;
      --surface: #121925;
      --surface-raised: #182131;
      --ink: #f8fafc;
      --muted: #bdc8d6;
      --line: #3e4a5e;
      --accent: #5eead4;
      --accent-ink: #99f6e4;
      --ok: #6ee7b7;
      --error: #fda4af;
      --warn: #fcd34d;
    }
    html[data-theme="dark"] body {
      background: var(--bg);
      color: var(--ink);
    }
    html[data-theme="dark"] input,
    html[data-theme="dark"] textarea,
    html[data-theme="dark"] select {
      border-color: var(--line);
      background: var(--surface-raised);
      color: var(--ink);
    }
    html[data-theme="dark"] button:not(.iab-theme-choice) { color: #042f2e; }
    html[data-theme="dark"] a.button:not(.secondary) { color: #042f2e; }
    html[data-theme="dark"] :focus-visible {
      outline: 3px solid #67e8f9;
      outline-offset: 3px;
    }
    .iab-theme-toggle {
      position: fixed;
      z-index: 1000;
      top: 12px;
      right: 12px;
      display: inline-flex;
      gap: 2px;
      padding: 3px;
      border: 1px solid var(--line, #d9dfdf);
      border-radius: 11px;
      background: color-mix(in srgb, var(--surface-raised, var(--surface, #fff)) 94%, transparent);
      box-shadow: 0 8px 28px rgb(0 0 0 / 18%);
      backdrop-filter: blur(12px);
      font: 600 12px/1.2 ui-sans-serif, system-ui, sans-serif;
    }
    .iab-theme-choice {
      min-height: 30px;
      padding: 5px 9px;
      border: 0;
      border-radius: 8px;
      color: var(--muted, #5f6b76);
      background: transparent;
      cursor: pointer;
      font: inherit;
    }
    .iab-theme-choice:hover {
      color: var(--ink, #1b1f23);
      background: color-mix(in srgb, var(--ink, #1b1f23) 8%, transparent);
    }
    .iab-theme-choice[aria-pressed="true"] {
      color: var(--surface, #fff);
      background: var(--ink, #1b1f23);
    }
    @media (max-width: 520px) {
      .iab-theme-toggle { top: 8px; right: 8px; }
      .iab-theme-choice { min-height: 28px; padding: 4px 7px; }
    }
  ` + "`" + `;
  document.head.append(style);

  function mountToggle() {
    const toggle = document.createElement("div");
    toggle.className = "iab-theme-toggle";
    toggle.setAttribute("role", "group");
    toggle.setAttribute("aria-label", "Color theme");
    for (const choice of choices) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "iab-theme-choice";
      button.dataset.themeChoice = choice;
      button.textContent = choice[0].toUpperCase() + choice.slice(1);
      button.addEventListener("click", () => {
        preference = choice;
        try {
          window.localStorage.setItem(storageKey, preference);
        } catch (_) {}
        applyTheme();
      });
      toggle.append(button);
    }
    document.body.append(toggle);
    applyTheme();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountToggle, { once: true });
  } else {
    mountToggle();
  }

  const systemChanged = () => {
    if (preference === "system") applyTheme();
  };
  if (media.addEventListener) media.addEventListener("change", systemChanged);
  else media.addListener(systemChanged);
})();`

func (s *Server) handleThemeScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(themeScript))
}
