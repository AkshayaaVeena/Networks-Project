import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  Chart as ChartJS,
  BarElement,
  ArcElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from "chart.js";
import { Bar, Pie } from "react-chartjs-2";

ChartJS.register(BarElement, ArcElement, CategoryScale, LinearScale, Tooltip, Legend);

export default function App() {
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("Fetching data...");

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const res = await axios.get("http://localhost:3000/latest");
        if (res.status === 202) {
          setStatus("Analysis in progress...");
        } else {
          setAnalysis(res.data);
          setStatus("Analysis ready ✅");
        }
      } catch (err) {
        console.error(err);
        setStatus("Backend not reachable ❌");
      }
    };

    fetchAnalysis();
    const interval = setInterval(fetchAnalysis, 50000);
    return () => clearInterval(interval);
  }, []);

  if (!analysis) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
        <h1 className="text-2xl font-bold">{status}</h1>
      </div>
    );
  }

  const appNames = Object.keys(analysis.apps || {});
  const scores = appNames.map((app) => analysis.apps[app].score);
  const packetLoss = appNames.map((app) => analysis.apps[app].packet_loss);
  const avgDelay = appNames.map((app) => analysis.apps[app].average_delay);

  // Collect TLS version usage across all apps
  const tlsVersionCounts = {};
  appNames.forEach((app) => {
    const sessions = analysis.apps[app].tls_sessions || [];
    sessions.forEach((s) => {
      const version = s.tls_version || "Unknown";
      tlsVersionCounts[version] = (tlsVersionCounts[version] || 0) + 1;
    });
  });

  const tlsLabels = Object.keys(tlsVersionCounts);
  const tlsValues = Object.values(tlsVersionCounts);

  return (
    <div className="min-h-screen bg-gray-950 text-white p-8">
      <h1 className="text-4xl font-bold text-center mb-6">
        🔍 Network Security Analysis Dashboard
      </h1>
      <p className="text-center text-gray-400 mb-8">{status}</p>

      {/* Summary */}
      <div className="bg-gray-800 p-6 rounded-lg shadow-lg mb-8 text-center">
        <h2 className="text-2xl mb-2 font-semibold">Overall Security Score</h2>
        <p className="text-5xl font-bold text-green-400">
          {Math.round(analysis.summary_score)} / 100
        </p>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Bar Chart - App Scores */}
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-xl font-semibold mb-4 text-center">App Security Scores</h2>
          <Bar
            data={{
              labels: appNames,
              datasets: [
                {
                  label: "Score",
                  data: scores,
                  backgroundColor: "rgba(75,192,192,0.6)",
                },
              ],
            }}
            options={{
              responsive: true,
              scales: {
                y: { beginAtZero: true, max: 100 },
              },
            }}
          />
        </div>

        {/* Pie Chart - TLS Versions */}
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-xl font-semibold mb-4 text-center">TLS Versions Used</h2>
          <Pie
            data={{
              labels: tlsLabels,
              datasets: [
                {
                  label: "TLS Usage",
                  data: tlsValues,
                  backgroundColor: [
                    "#34d399",
                    "#60a5fa",
                    "#fbbf24",
                    "#f87171",
                    "#a78bfa",
                  ],
                },
              ],
            }}
            options={{ responsive: true }}
          />
        </div>
      </div>

      {/* App Details Table */}
      <div className="bg-gray-800 p-6 rounded-lg shadow-lg mt-10">
        <h2 className="text-2xl font-semibold mb-4 text-center">App Details</h2>
        <table className="w-full text-left text-gray-200 border-collapse">
          <thead className="bg-gray-700">
            <tr>
              <th className="p-3">App Name</th>
              <th className="p-3">Score</th>
              <th className="p-3">Packet Loss (%)</th>
              <th className="p-3">Avg Delay (s)</th>
              <th className="p-3">Notifications</th>
              <th className="p-3">Suspicious Domains</th>
            </tr>
          </thead>
          <tbody>
            {appNames.map((app) => {
              const a = analysis.apps[app];
              const suspicious = a.domains_contacted.filter((d) =>
                ["tracker.com", "malicious.site", "ads.example"].includes(d)
              );
              return (
                <tr
                  key={app}
                  className="hover:bg-gray-700 border-b border-gray-700"
                >
                  <td className="p-3 font-semibold">{app}</td>
                  <td className="p-3">{a.score}</td>
                  <td className="p-3">{a.packet_loss}</td>
                  <td className="p-3">{a.average_delay}</td>
                  <td className="p-3">{a.notifications}</td>
                  <td className="p-3 text-red-400">
                    {suspicious.length > 0 ? suspicious.join(", ") : "None"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}


