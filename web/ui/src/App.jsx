import { useState, useEffect } from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js';
import './App.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

function App() {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState('');
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [engines, setEngines] = useState([]);
  const [tpData, setTpData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch projects
  useEffect(() => {
    fetch('/api/projects/summary')
      .then(res => res.json())
      .then(data => {
        const uniqueProjects = [...new Set(data.map(item => item.name.split('/')[0]))];
        setProjects(uniqueProjects ?? []);
      });
  }, []);

  // Fetch repos when project changes
  useEffect(() => {
    if (selectedProject) {
      fetch(`/api/repos?prefix=${selectedProject}`)
        .then(res => res.json())
        .then(data => setRepos(Array.isArray(data) ? data : []));
      setSelectedRepo('');
      setEngines([]);
    } else {
      setRepos([]);
      setEngines([]);
      setSelectedRepo('');
    }
  }, [selectedProject]);

  // Fetch engines when repo changes
  useEffect(() => {
    if (selectedRepo) {
      const fullRepoName = `${selectedProject}/${selectedRepo}`;
      fetch(`/api/engines/${encodeURIComponent(fullRepoName)}`)
        .then(res => res.json())
        .then(data => setEngines(Array.isArray(data) ? data : []));
    } else {
      setEngines([]);
    }
  }, [selectedRepo, selectedProject]);

  // Fetch TP data for "All" and for each engine
  const fetchTpData = async () => {
    setLoading(true);
    setError(null);
    const fullRepoName = `${selectedProject}/${selectedRepo}`;
    let bars = [];

    // Fetch "All"
    try {
      const resAll = await fetch(`/api/tp-percentage/repo/${encodeURIComponent(fullRepoName)}`);
      if (!resAll.ok) throw new Error("Backend error (All)");
      const dataAll = await resAll.json();
      bars.push({
        label: 'All',
        tpPercentage: (dataAll.tpPercentage ?? 0) * 100,
        vulnCount: dataAll.vulnerabilityCount ?? 0,
      });
    } catch (e) {
      setError(e.message);
      setLoading(false);
      return;
    }

    // Usa sempre o array engines do estado (não faz fetch duplicado)
    for (const engine of engines) {
      try {
        const res = await fetch(`/api/tp-percentage/engine/${engine}?repo=${encodeURIComponent(fullRepoName)}`);
        if (!res.ok) continue;
        const data = await res.json();
        bars.push({
          label: engine,
          tpPercentage: (data.tpPercentage ?? 0) * 100,
          vulnCount: data.vulnerabilityCount ?? 0,
        });
      } catch {
        // Ignora erros individuais
      }
    }

    setTpData(bars);
    setLoading(false);
  };

  return (
    <div className="container">
      <h1>AST-Benchmark</h1>
      <div className="dashboard-filters">
        <div className="filter-group">
          <label>Project</label>
          <select value={selectedProject} onChange={e => setSelectedProject(e.target.value)}>
            <option value="">Select Project</option>
            {projects.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label>Repository</label>
          <select value={selectedRepo} onChange={e => setSelectedRepo(e.target.value)} disabled={!selectedProject}>
            <option value="">Select Repo</option>
            {repos.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        <button
          className="calculate-button"
          onClick={fetchTpData}
          disabled={loading || !selectedRepo || engines.length === 0}
        >
          {loading ? 'Loading...' : 'Show Results'}
        </button>
      </div>
      <div className="chart-container">
        {error && <p className="error">Error: {error}</p>}
        {!loading && tpData.length > 0 && (
          <Bar
            data={{
              labels: tpData.map(d => d.label),
              datasets: [
                {
                  label: 'True Positive %',
                  data: tpData.map(d => d.tpPercentage),
                  backgroundColor: 'rgba(54, 162, 235, 0.6)',
                },
              ],
            }}
            options={{
              plugins: {
                tooltip: {
                  callbacks: {
                    label: function(context) {
                      const idx = context.dataIndex;
                      const tp = tpData[idx]?.tpPercentage ?? 0;
                      const vuln = tpData[idx]?.vulnCount ?? 0;
                      return `TP %: ${tp.toFixed(1)} | Vulns: ${vuln}`;
                    }
                  }
                },
                datalabels: {
                  display: true,
                  anchor: 'end',
                  align: 'top',
                  formatter: function(value, context) {
                    const vuln = tpData[context.dataIndex]?.vulnCount ?? 0;
                    return vuln > 0 ? vuln : '';
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
        {!loading && tpData.length === 0 && !error && (
          <p>Choose filters and click "Show TP %" to see results.</p>
        )}
      </div>
    </div>
  );
}

export default App;