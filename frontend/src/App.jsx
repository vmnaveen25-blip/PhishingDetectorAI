import { useState } from "react";
import "./App.css";

function App() {

  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  async function analyzeWebsite() {

    if (url.trim() === "") {
      alert("Please enter a website URL");
      return;
    }

    setLoading(true);
    setResult(null);

    try {

      const response = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.log("Backend Error:", errorText);
        alert(`Backend Error (${response.status})`);
        setLoading(false);
        return;
      }

      const data = await response.json();

      console.log("Prediction:", data);

      setResult(data);

    } catch (error) {

      console.error("Fetch Error:", error);

      alert("Cannot connect to FastAPI server.\nCheck backend terminal.");

    }

    setLoading(false);
  }

  return (
    <div className="app">

      <h1>🛡 AI Phishing Detector</h1>

      <input
        type="text"
        placeholder="Enter Website URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={analyzeWebsite}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {result && (
        <div className="result">

          <h2>{result.result}</h2>

          <h3>
            Confidence: {result.confidence}%
          </h3>

          <p>
            URL: {result.url}
          </p>

        </div>
      )}

    </div>
  );
}

export default App;