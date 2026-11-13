// Strack: live regions, match clock and judge notifications. No dependencies, no inline code.
(function () {
  // Theme: the system preference until the person picks light or dark (kept in this browser only).
  var root = document.documentElement;
  try {
    var saved = window.localStorage.getItem("strack-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) { /* storage blocked: follow the system */ }
  document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
    button.addEventListener("click", function () {
      var current = root.getAttribute("data-theme")
        || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { window.localStorage.setItem("strack-theme", next); } catch (e) { /* ignore */ }
    });
  });

  "use strict";

  var live = document.querySelector("[data-live]");
  function announce(text) {
    if (!live) return;
    live.textContent = "";
    window.setTimeout(function () { live.textContent = text; }, 50);
  }

  // Match clock: synced from the server, extrapolated locally between syncs. The same clock shows in
  // the top bar chip and in the sidebar card (teams, state, segmented progress, minute).
  var clockValues = document.querySelectorAll("[data-clock-value]");
  var clockStates = document.querySelectorAll("[data-clock-state]");
  var clockTeams = document.querySelectorAll("[data-clock-teams]");
  var clockMinutes = document.querySelectorAll("[data-clock-minute]");
  var clockProgress = document.querySelector("[data-clock-progress]");
  var clockSegments = document.querySelector("[data-clock-segments]");
  var clockValue = clockValues.length ? clockValues[0] : null;
  var sample = null;
  function setText(nodes, text) {
    nodes.forEach(function (n) { if (n.textContent !== text) n.textContent = text; });
  }
  function setState(text, live) {
    clockStates.forEach(function (n) {
      n.textContent = text;
      if (live) n.setAttribute("data-live-state", "live");
      else n.removeAttribute("data-live-state");
    });
  }
  function setProgress(minute, end) {
    if (clockProgress) {
      clockProgress.max = end;
      clockProgress.value = Math.max(0, Math.min(minute, end));
    }
    if (clockSegments) {
      var parts = clockSegments.children;
      var on = Math.round((Math.max(0, Math.min(minute, end)) / end) * parts.length);
      for (var i = 0; i < parts.length; i++) parts[i].classList.toggle("on", i < on);
    }
  }
  function renderClock() {
    if (!clockValue || !sample) return;
    if (!sample.synced) {
      setText(clockValues, "sin conexión");
      setText(clockMinutes, "Sin conexión con el partido");
      setState("Partido", false);
      setProgress(0, 105);
      return;
    }
    var minute = sample.minute + ((performance.now() - sample.at) / 60000) * sample.speedup;
    var over = minute >= sample.end;
    var seconds = Math.max(0, Math.floor(minute * 60));
    var ss = seconds % 60;
    setText(clockValues, over ? "Final" : Math.floor(seconds / 60) + ":" + (ss < 10 ? "0" : "") + ss);
    setText(clockMinutes, over ? "Partido terminado" : "Minuto " + Math.floor(minute) + " de " + Math.round(sample.end));
    setState(over ? "Finalizado" : "En vivo", !over);
    setProgress(minute, sample.end);
  }
  // The match a page is about (`data-match-key` anywhere in it); the first match otherwise.
  var pageMatch = document.querySelector("[data-match-key]");
  var clockUrl = "/api/clock" + (pageMatch ? "?partido=" + encodeURIComponent(pageMatch.getAttribute("data-match-key")) : "");
  function syncClock() {
    fetch(clockUrl, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        sample = { minute: data.minute, speedup: data.speedup, end: data.end_min, synced: data.synced, at: performance.now() };
        var teams = data.teams ? data.teams + (data.live > 1 ? " · " + data.live + " en vivo" : "") : "";
        setText(clockTeams, teams);
        renderClock();
      })
      .catch(function () {});
  }
  if (clockValue) {
    syncClock();
    window.setInterval(syncClock, 5000);
    window.setInterval(renderClock, 500);
  }

  // "Cargar sitios": a chosen file fills the text box, which stays editable before sending.
  document.querySelectorAll("[data-file-field]").forEach(function (field) { field.hidden = false; });
  document.querySelectorAll("[data-file-into]").forEach(function (input) {
    input.addEventListener("change", function () {
      var target = document.getElementById(input.getAttribute("data-file-into"));
      var file = input.files && input.files[0];
      if (!target || !file) return;
      if (file.size > 1048576) { announce("El archivo supera 1 MB: dividilo en partes."); return; }
      var reader = new FileReader();
      reader.onload = function () {
        target.value = String(reader.result || "");
        announce("Archivo leído: revisá el contenido y confirmá la carga.");
      };
      reader.readAsText(file);
    });
  });

  // Step-by-step forms ("Pedir acceso"): one step at a time, typed values kept when going back, the
  // browser's back and forward walk the steps. Without script every step shows at once.
  document.querySelectorAll("[data-steps]").forEach(function (form) {
    var steps = Array.prototype.slice.call(form.querySelectorAll("[data-step]"));
    var stepper = document.querySelector("[data-stepper]");
    var status = document.querySelector("[data-step-status]");
    if (steps.length < 2) return;
    form.querySelectorAll("[data-step-nav]").forEach(function (n) { n.hidden = false; });
    form.querySelectorAll("[data-step-back]").forEach(function (b) { b.hidden = false; });
    var current = 0;
    function show(i, focus) {
      current = Math.max(0, Math.min(i, steps.length - 1));
      steps.forEach(function (s, n) { s.hidden = n !== current; });
      if (stepper) {
        Array.prototype.forEach.call(stepper.children, function (li, n) {
          li.classList.toggle("done", n < current);
          if (n === current) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
        });
      }
      if (status) status.textContent = "Paso " + (current + 1) + " de " + steps.length;
      if (focus) {
        var first = steps[current].querySelector("input:not([type=hidden]), select, textarea");
        if (first) first.focus();
      }
    }
    function valid(step) {
      var fields = step.querySelectorAll("input, select, textarea");
      for (var i = 0; i < fields.length; i++) {
        if (!fields[i].checkValidity()) { fields[i].reportValidity(); return false; }
      }
      return true;
    }
    form.addEventListener("click", function (event) {
      var next = event.target.closest("[data-step-next]");
      var back = event.target.closest("[data-step-back]");
      if (next && valid(steps[current])) {
        show(current + 1, true);
        history.pushState({ step: current }, "", "#paso-" + (current + 1));
      } else if (back) {
        history.back();
      }
    });
    // Enter in a field moves on instead of sending the form before the last step.
    form.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" || event.target.tagName === "TEXTAREA" || current === steps.length - 1) return;
      event.preventDefault();
      var next = steps[current].querySelector("[data-step-next]");
      if (next) next.click();
    });
    window.addEventListener("popstate", function (event) {
      var step = event.state && typeof event.state.step === "number" ? event.state.step : 0;
      show(step, true);
    });
    var start = Math.max(1, parseInt(form.getAttribute("data-start") || "1", 10)) - 1;
    history.replaceState({ step: start }, "", start ? "#paso-" + (start + 1) : location.pathname);
    show(start, start > 0);
  });

  // Browser notifications for judges (opt-in, needs a click).
  var notifyButton = document.querySelector("[data-enable-notifications]");
  if (notifyButton) {
    if (!("Notification" in window)) {
      notifyButton.hidden = true;
    } else {
      var syncButton = function () {
        if (Notification.permission === "granted") {
          notifyButton.textContent = "Avisos del navegador activados";
          notifyButton.disabled = true;
        } else if (Notification.permission === "denied") {
          notifyButton.textContent = "Avisos bloqueados en este navegador";
          notifyButton.disabled = true;
        }
      };
      syncButton();
      notifyButton.addEventListener("click", function () {
        Notification.requestPermission().then(syncButton);
      });
    }
  }

  // Server-rendered regions that refresh themselves when their version changes.
  var baseTitle = document.title;
  document.querySelectorAll("[data-refresh]").forEach(function (region) {
    var url = region.getAttribute("data-refresh");
    var version = region.getAttribute("data-version");
    var tracksPending = region.hasAttribute("data-pending");
    var pending = parseInt(region.getAttribute("data-pending") || "0", 10);
    var every = parseInt(region.getAttribute("data-interval") || "2000", 10);
    if (tracksPending && pending > 0) document.title = "(" + pending + ") " + baseTitle;

    function tick() {
      fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } })
        .then(function (r) {
          if (r.status === 401) { window.location.href = "/login"; return null; }
          if (!r.ok) return null;
          var next = r.headers.get("X-Version");
          if (next !== null && next === version) return null;
          var nextPending = parseInt(r.headers.get("X-Pending") || "0", 10);
          return r.text().then(function (html) {
            var active = document.activeElement;
            var inside = active && region.contains(active);
            // Never swap the content under a form the judge is using.
            if (inside && active.closest("form")) return;
            var focusHref = inside ? active.getAttribute("href") : null;
            region.innerHTML = html;
            version = next;
            if (focusHref) {
              var again = region.querySelector('a[href="' + focusHref + '"]');
              if (again) again.focus();
            }
            if (!tracksPending) return;
            document.title = nextPending > 0 ? "(" + nextPending + ") " + baseTitle : baseTitle;
            if (nextPending > pending) {
              var text = nextPending === 1 ? "Hay 1 pendiente de firma" : "Hay " + nextPending + " pendientes de firma";
              announce(text);
              if ("Notification" in window && Notification.permission === "granted" && document.hidden) {
                try { new Notification("Strack", { body: text, tag: "strack-inbox" }); } catch (e) { /* ignore */ }
              }
            }
            pending = nextPending;
          });
        })
        .catch(function () {});
    }
    window.setInterval(tick, every);
  });

  // Signing forms submit once.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form.hasAttribute("data-once")) return;
    window.setTimeout(function () {
      form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; });
    }, 0);
  });

  // Modal dialogs: links with data-dialog-open open the dialog (and fall back to their page).
  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-dialog-open]");
    if (opener) {
      var dialog = document.getElementById(opener.getAttribute("data-dialog-open"));
      if (dialog && typeof dialog.showModal === "function") {
        event.preventDefault();
        dialog.showModal();
        var first = dialog.querySelector("input:not([type=hidden]), select, textarea");
        if (first) first.focus();
      }
      return;
    }
    var closer = event.target.closest("[data-dialog-close]");
    if (closer) {
      var open = closer.closest("dialog");
      if (open) open.close();
    }
  });
  document.querySelectorAll("dialog.modal").forEach(function (dialog) {
    // A click on the backdrop (outside the box) closes it, like Escape does.
    dialog.addEventListener("click", function (event) {
      if (event.target !== dialog) return;
      var box = dialog.getBoundingClientRect();
      var inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top && event.clientY <= box.bottom;
      if (!inside) dialog.close();
    });
  });

  // Fields that only apply to judges follow the role select.
  document.querySelectorAll("[data-role-select]").forEach(function (select) {
    var form = select.closest("form");
    function sync() {
      form.querySelectorAll("[data-judge-only]").forEach(function (block) {
        block.hidden = select.value !== "judge";
      });
      form.querySelectorAll("[data-platform-only]").forEach(function (block) {
        block.hidden = select.value !== "platform";
      });
    }
    select.addEventListener("change", sync);
    sync();
  });

  // Filter selects apply on change (the Filter button stays for keyboard and no-script use).
  document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () {
      if (select.form) select.form.submit();
    });
  });
})();
