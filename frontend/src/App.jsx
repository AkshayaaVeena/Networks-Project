import React, { useState, useEffect } from "react";
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

// Register Chart.js modules
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Legend,
  Tooltip
);

const App = () => {
  const [data, setData] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  // Fetch analysis from backend
  const fetchData = async () => {
    try {
      setRefreshing(true);
      const res = await axios.get("http://127.0.0.1:3000/latest");
      setData(res.data);
      setRefreshing(false);
    } catch (err) {
      console.error("Error fetching analysis:", err);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // refresh every 10s
    return () => clearInterval(interval);
  }, []);

  if (!data) return <div className="p-4 text-center">Loading analysis...</div>;

  const apps = Object.entries(data.apps || {});
  const appNames = apps.map(([name]) => name);
  const appScores = apps.map(([_, app]) => app.score);
  const packetLoss = apps.map(([_, app]) => app.packet_loss);
  const avgDelay = apps.map(([_, app]) => app.average_delay);

  // Bar chart for app scores
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

  // Line chart for packet loss vs delay
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
      <h1 className="text-3xl font-bold mb-4 text-center">
        App Security Analysis Dashboard
      </h1>
      <p className="text-center mb-6">
        Overall Summary Score:{" "}
        <span className="font-semibold">{Math.round(data.summary_score)}</span>
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

      {/* Table for detailed app info */}
      <div>
        <h3 className="font-semibold mb-2">App Session Details</h3>
        {apps.map(([appName, app]) => (
          <div key={appName} className="mb-6">
            <h4 className="font-semibold text-lg mb-2">{appName}</h4>
            <p>
              Notifications: {app.notifications} | QUIC Used:{" "}
              {app.quic_used ? "Yes" : "No"} | Packet Loss: {app.packet_loss}% | Avg Delay:{" "}
              {app.average_delay}s | Score: {app.score}
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
                {app.session_details.map((s, idx) => (
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
