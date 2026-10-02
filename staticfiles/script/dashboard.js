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

  // Initial default chart structure
  trafficChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: ["00:00", "00:15", "00:30", "00:45", "Now"], // Placeholder labels until fetch finishes
      datasets: [
        {
          label: "Total Requests",
          data: [0, 0, 0, 0, 0],
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.15)",
          borderWidth: 2,
          tension: 0.3,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
        },
        {
          label: "Blocked Threats",
          data: [0, 0, 0, 0, 0],
          borderColor: "#f87171",
          backgroundColor: "rgba(248, 113, 113, 0.15)",
          borderWidth: 2,
          tension: 0.3,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
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
          beginAtZero: true,
          grid: { color: "#1c2233" },
          ticks: {
            stepSize: 1,
            color: "#7c8699",
            font: { size: 11, family: "JetBrains Mono, monospace" },
            callback: (value) => Number.isInteger(value) ? value : "",
          },
        },
      },
    },
  });

  fetchTrafficData();
}

function fetchTrafficData() {
  const canvas = document.getElementById("trafficChart");
  const trafficUrl = canvas?.dataset.trafficUrl;
  if (!trafficUrl) return;

  fetch(trafficUrl, { headers: { "X-Requested-With": "XMLHttpRequest" } })
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
    fetchTrafficData();
  });
}
