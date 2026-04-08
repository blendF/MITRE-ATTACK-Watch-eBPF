(function () {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = proto + "//" + window.location.host + "/ws";
  const tbody = document.querySelector("#events tbody");
  if (!tbody) return;

  function rowClass(sev) {
    if (sev === "critical") return "sev-critical";
    if (sev === "medium") return "sev-medium";
    return "sev-low";
  }

  function fmtTime(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleString();
    } catch (_) {
      return iso;
    }
  }

  function techniqueSummary(matches) {
    if (!matches || !matches.length) return "—";
    return matches
      .map(function (m) {
        return m.technique_id;
      })
      .join(", ");
  }

  function addRow(payload) {
    const tr = document.createElement("tr");
    tr.className = rowClass(payload.severity);
    tr.addEventListener("click", function () {
      window.location.href = "/log/" + encodeURIComponent(payload.id);
    });
    const ev = payload.event || {};
    tr.innerHTML =
      "<td class=\"mono\">" +
      fmtTime(payload.observed_at) +
      "</td><td><span class=\"pill " +
      rowClass(payload.severity) +
      "\">" +
      payload.severity +
      "</span></td><td class=\"mono\">" +
      (ev.type || "") +
      "</td><td class=\"mono\">" +
      (ev.command || "").replace(/</g, "&lt;") +
      "</td><td class=\"mono\">" +
      techniqueSummary(payload.matches) +
      "</td>";
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > 500) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  const sock = new WebSocket(wsUrl);
  sock.onmessage = function (ev) {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (_) {
      return;
    }
    if (msg && msg.id && msg.event) {
      addRow(msg);
    }
  };
  sock.onerror = function () {
    console.warn("websocket error");
  };
})();
