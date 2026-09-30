let trafficChartInstance = null;

document.addEventListener("DOMContentLoaded", function () {
  initTrafficChart();
  initDistributionRing();
  initRefreshButton();
});

function initTrafficChart() {
  const canvas = document.getElementById("trafficChart");
  if (!canvas || typeof Chart === "undefined") return;

  const ctx = canvas.getContext("2d");

  const totalGradient = ctx.createLinearGradient(0, 0, 0, canvas.parentElement.clientHeight);
  totalGradient.addColorStop(0, "rgba(59, 130, 246, 0.25)");
  totalGradient.addColorStop(1, "rgba(59, 130, 246, 0)");

  const blockedGradient = ctx.createLinearGradient(0, 0, 0, canvas.parentElement.clientHeight);
  blockedGradient.addColorStop(0, "rgba(248, 113, 113, 0.25)");
  blockedGradient.addColorStop(1, "rgba(248, 113, 113, 0)");

  trafficChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Total Requests",
          data: [],
          borderColor: "#3b82f6",
          backgroundColor: totalGradient,
          borderWidth: 2,
          tension: 0.4,
          fill: true,
          pointRadius: 0,
        },
        {
          label: "Blocked Threats",
          data: [],
          borderColor: "#f87171",
          backgroundColor: blockedGradient,
          borderWidth: 2,
          tension: 0.4,
          fill: true,
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#0d1220",
          borderColor: "#1c2233",
          borderWidth: 1,
          titleColor: "#e6eaf2",
          bodyColor: "#7c8699",
          padding: 10,
          displayColors: true,
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: "#7c8699", font: { size: 11, family: "JetBrains Mono, monospace" } },
        },
        y: {
          grid: { color: "#1c2233" },
          ticks: {
            color: "#7c8699",
            font: { size: 11, family: "JetBrains Mono, monospace" },
            callback: (value) => (value >= 1000 ? value / 1000 + "k" : value),
          },
        },
      },
    },
  });

  fetchTrafficData();
}

/**
 * Pulls real bucketed counts from the backend and updates the chart in place.
 */
function fetchTrafficData() {
  fetch("/traffic-data/", { headers: { "X-Requested-With": "XMLHttpRequest" } })
    .then((res) => {
      if (!res.ok) throw new Error(`Traffic data request failed: ${res.status}`);
      return res.json();
    })
    .then((data) => {
      if (!trafficChartInstance) return;
      trafficChartInstance.data.labels = data.labels;
      trafficChartInstance.data.datasets[0].data = data.total_requests;
      trafficChartInstance.data.datasets[1].data = data.blocked_threats;
      trafficChartInstance.update();
    })
    .catch((err) => console.error("Failed to load traffic data:", err));
}

function initDistributionRing() {
  // unchanged
  const ring = document.getElementById("distributionRing");
  if (!ring) return;

  const segments = [
    { key: "critical", color: "#f87171" },
    { key: "high", color: "#fb923c" },
    { key: "medium", color: "#facc15" },
    { key: "low", color: "#4ade80" },
  ];

  let cursor = 0;
  const stops = segments.map((seg) => {
    const value = parseFloat(ring.dataset[seg.key]) || 0;
    const start = cursor;
    cursor += value;
    return `${seg.color} ${start}% ${cursor}%`;
  });

  ring.style.setProperty("--ring-gradient", stops.join(", "));
}

function initRefreshButton() {
  const btn = document.getElementById("refreshBtn");
  if (!btn) return;

  btn.addEventListener("click", function () {
    btn.classList.add("spinning");
    setTimeout(() => btn.classList.remove("spinning"), 600);
    fetchTrafficData(); // now actually refreshes the chart data
  });
}