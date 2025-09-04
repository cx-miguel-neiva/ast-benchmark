import { useState, useEffect } from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js';
import './App.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

function App() {
  const [benchmarkData, setBenchmarkData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState('');

  // Fetch benchmark data
  const fetchBenchmarkData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const res = await fetch('/api/benchmark');
      if (!res.ok) throw new Error("Failed to fetch benchmark data");
      const data = await res.json();
      setBenchmarkData(data);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchBenchmarkData();
  }, []);

  // Get repository options
  const repositories = benchmarkData?.repositories || [];
  
  // Get chart data for selected repository
  const getChartData = () => {
    if (!selectedRepo || !benchmarkData) return null;

    const repo = repositories.find(r => r.repositoryName === selectedRepo);
    if (!repo) return null;

    const labels = ['All', ...Object.keys(repo.engines)];
    const data = [
      repo.all.tpPercentage,
      ...Object.values(repo.engines).map(engine => engine.tpPercentage)
    ];

    return {
      labels,
      datasets: [{
        label: 'True Positive Percentage (%)',
        data,
        backgroundColor: [
          'rgba(54, 162, 235, 0.8)',
          'rgba(255, 99, 132, 0.8)',
          'rgba(255, 205, 86, 0.8)',
          'rgba(75, 192, 192, 0.8)',
        ],
        borderColor: [
          'rgba(54, 162, 235, 1)',
          'rgba(255, 99, 132, 1)',
          'rgba(255, 205, 86, 1)',
          'rgba(75, 192, 192, 1)',
        ],
        borderWidth: 1,
      }]
    };
  };

  return (
    <div className="container">
      <h1>AST-Benchmark</h1>
      
      {error && <p className="error">Error: {error}</p>}
      {loading && <p>Loading...</p>}
      
      {benchmarkData && (
        <>
          <div style={{ marginBottom: '20px' }}>
            <h2>Overall Score: {benchmarkData.overallScore.tpPercentage.toFixed(2)}%</h2>
          </div>
          
          <div className="dashboard-filters">
            <div className="filter-group">
              <label>Repository</label>
              <select value={selectedRepo} onChange={e => setSelectedRepo(e.target.value)}>
                <option value="">Select Repository</option>
                {repositories.map(repo => (
                  <option key={repo.repositoryName} value={repo.repositoryName}>
                    {repo.repositoryName}
                  </option>
                ))}
              </select>
            </div>
          </div>
          
          <div className="chart-container">
            {selectedRepo && getChartData() && (
              <Bar
                data={getChartData()}
                options={{
                  plugins: {
                    tooltip: {
                      callbacks: {
                        label: function(context) {
                          const value = context.raw;
                          return `TP %: ${value.toFixed(1)}`;
                        }
                      }
                    },
                    datalabels: {
                      display: true,
                      anchor: 'end',
                      align: 'top',
                      formatter: function(value) {
                        return value > 0 ? value.toFixed(1) + '%' : '';
                      }
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      max: 100,
                      title: { display: true, text: 'TP %' },
                      ticks: {
                        stepSize: 2
                      }
                    },
                  },
                }}
              />
            )}
            {!selectedRepo && !error && (
              <p>Select a repository to see results.</p>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default App;