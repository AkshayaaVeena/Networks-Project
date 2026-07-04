import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { Bar, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Legend,
  Tooltip,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Legend,
  Tooltip
);

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:3000";
const POLL_INTERVAL_MS = 10000;

const App = () => {
  const [status, setStatus] = useState("loading");
  const [data, setData] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [triggering, setTriggering] = useState(false);

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await axios.get(`${API_BASE_URL}/latest`);

      if (res.data && res.data.apps) {
        setData(res.data);
        setStatus("ready");
        setErrorMessage(null);
      } else if (res.data && res.data.status === "analysis in progress") {
        setStatus("in-progress");
      } else {
        setStatus("empty");
      }
    } catch (err) {
      if (err.response && err.response.status === 404) {
        setStatus("empty");
      } else if (err.response && err.response.status === 500) {
        setStatus("error");
        setErrorMessage(err.response.data?.error || "Analysis failed.");
      } else {
        setStatus("error");
        setErrorMessage("Could not reach the backend API.");
      }
      console.error("Error fetching analysis:", err);
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  const triggerCapture = async () => {
    setTriggering(true);
    try {
      await axios.post(`${API_BASE_URL}/upload`, {
        app: "manual-trigger",
        title: "Manual capture",
        text: "Triggered from dashboard",
      });
      setStatus("in-progress");
      setTimeout(fetchData, 1000);
    } catch (err) {
      setStatus("error");
      setErrorMessage("Could not start a new capture.");
      console.error("Error triggering capture:", err);
    } finally {
      setTriggering(false);
    }
  };

  const TriggerButton = (
    <button
      onClick={triggerCapture}
      disabled={triggering || status === "in-progress"}
      className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {triggering ? "Starting..." : "Trigger New Capture"}
    </button>
  );

  if (status === "loading") {
    return <div className="p-4 text-center">Loading analysis...</div>;
  }

  if (status === "in-progress") {
    return (
      <div className="max-w-2xl mx-auto p-6 text-center">
        <h1 className="text-2xl font-bold mb-4">App Security Analysis Dashboard</h1>
        <p className="text-gray-600">Capture in progress, analyzing traffic...</p>
        <p className="text-sm text-gray-400 mt-1">This refreshes automatically.</p>
      </div>
    );
  }

  if (status === "empty") {
    return (
      <div className="max-w-2xl mx-auto p-6 text-center">
        <h1 className="text-2xl font-bold mb-4">App Security Analysis Dashboard</h1>
        <p className="text-gray-600 mb-4">No analysis available yet.</p>
        {TriggerButton}
      </div>
    );
  }

  if (status === "error") {
    return (
      <div className="max-w-2xl mx-auto p-6 text-center">
        <h1 className="text-2xl font-bold mb-4">App Security Analysis Dashboard</h1>
        <p className="text-red-600 mb-4">{errorMessage || "Something went wrong."}</p>
        <button
          onClick={fetchData}
          className="px-4 py-2 bg-gray-600 text-white rounded"
        >
          Retry
        </button>
      </div>
    );
  }

  const apps = Object.entries(data.apps || {});
  const measuredApps = apps.filter(([, app]) => app.measured);
  const appNames = measuredApps.map(([name]) => name);
  const appScores = measuredApps.map(([, app]) => app.score);
  const packetLoss = measuredApps.map(([, app]) => app.packet_loss);
  const avgDelay = measuredApps.map(([, app]) => app.average_delay);

  const scoreBarData = {
    labels: appNames,
    datasets: [
      {
        label: "App Security Score",
        data: appScores,
        backgroundColor: "rgba(54, 162, 235, 0.6)",
      },
    ],
  };

  const delayLossLineData = {
    labels: appNames,
    datasets: [
      {
        label: "Packet Loss (%)",
        data: packetLoss,
        borderColor: "rgba(255, 99, 132, 0.8)",
        backgroundColor: "rgba(255, 99, 132, 0.2)",
        tension: 0.3,
      },
      {
        label: "Average Delay (s)",
        data: avgDelay,
        borderColor: "rgba(75, 192, 192, 0.8)",
        backgroundColor: "rgba(75, 192, 192, 0.2)",
        tension: 0.3,
      },
    ],
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-3xl font-bold text-center flex-1">
          App Security Analysis Dashboard
        </h1>
        {TriggerButton}
      </div>
      <p className="text-center mb-6">
        Overall Summary Score:{" "}
        <span className="font-semibold">{Math.round(data.summary_score ?? 0)}</span>
      </p>

      {refreshing && (
        <p className="text-center text-sm text-gray-500">Refreshing...</p>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div>
          <h3 className="font-semibold mb-2">App Security Scores</h3>
          <Bar data={scoreBarData} options={{ responsive: true }} />
        </div>
        <div>
          <h3 className="font-semibold mb-2">Packet Loss & Average Delay</h3>
          <Line data={delayLossLineData} options={{ responsive: true }} />
        </div>
      </div>

      <div>
        <h3 className="font-semibold mb-2">App Session Details</h3>
        {apps.map(([appName, app]) => (
          <div key={appName} className="mb-6">
            <h4 className="font-semibold text-lg mb-2">{appName}</h4>
            <p>
              Notifications: {app.notifications} | QUIC Used:{" "}
              {app.quic_used ? "Yes" : "No"} | Packet Loss: {app.packet_loss}% | Avg Delay:{" "}
              {app.average_delay}s | Score:{" "}
              {app.measured ? app.score : "Not observed during capture"}
            </p>

            <table className="w-full border-collapse border border-gray-300 mt-2">
              <thead>
                <tr className="bg-gray-200">
                  <th className="border px-2 py-1">TLS Version</th>
                  <th className="border px-2 py-1">Cipher</th>
                  <th className="border px-2 py-1">Certificate Strength</th>
                  <th className="border px-2 py-1">Uses HTTP</th>
                  <th className="border px-2 py-1">Suspicious Domain</th>
                  <th className="border px-2 py-1">Session Score</th>
                  <th className="border px-2 py-1">Note</th>
                </tr>
              </thead>
              <tbody>
                {(app.session_details || []).map((s, idx) => (
                  <tr key={idx} className="text-center">
                    <td className="border px-2 py-1">{s.tls_version}</td>
                    <td className="border px-2 py-1">{s.cipher || "-"}</td>
                    <td className="border px-2 py-1">{s.certificate_strength}</td>
                    <td className="border px-2 py-1">{s.uses_http ? "Yes" : "No"}</td>
                    <td className="border px-2 py-1">{s.suspicious_domain ? "Yes" : "No"}</td>
                    <td className="border px-2 py-1">{s.session_score}</td>
                    <td className="border px-2 py-1">{s.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </div>
  );
};

export default App;
