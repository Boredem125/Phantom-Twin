import React, { useState } from 'react';
import { Database, Loader2, Play, Search, Shield } from 'lucide-react';
import type { Alert, RagAnswer } from '../types/PhantomTwin';

interface InvestigationPanelProps {
  onSelectEntity: (entityId: string) => void;
  onSelectAlert: (alert: Alert) => void;
  alerts: Alert[];
}

const host = '127.0.0.1:8000';
const API_BASE = `http://${host}`;

const starterQueries = [
  'How many attempts from India?',
  'How many privilege escalation possibilities?',
  'How many Phantom decoys are active?',
];

export const InvestigationPanel: React.FC<InvestigationPanelProps> = ({ onSelectEntity, onSelectAlert, alerts }) => {
  const [question, setQuestion] = useState(starterQueries[0]);
  const [answer, setAnswer] = useState<RagAnswer | null>(null);
  const [isDemoStarting, setIsDemoStarting] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);
  const [demoMessage, setDemoMessage] = useState('Ready to lure a scripted attacker into Phantom Twin.');

  const startLiveDemo = async () => {
    setIsDemoStarting(true);
    setDemoMessage('Starting live attack sequence...');
    try {
      const res = await fetch(`${API_BASE}/api/demo/live-attack`, { method: 'POST' });
      const data = await res.json();
      setDemoMessage(data.message || 'Live demo started.');
    } catch {
      setDemoMessage('Backend unreachable. Start FastAPI on port 8000 and retry.');
    } finally {
      setIsDemoStarting(false);
    }
  };

  const askRag = async (query = question) => {
    const trimmed = query.trim();
    if (!trimmed) return;
    setQuestion(trimmed);
    setIsQuerying(true);
    try {
      const res = await fetch(`${API_BASE}/api/rag/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: trimmed }),
      });
      if (!res.ok) throw new Error('Query failed');
      setAnswer(await res.json());
    } catch {
      setAnswer({
        question: trimmed,
        answer: 'Investigation service is unreachable. Start the backend and run the demo again.',
        evidence: [],
        pinecone_status: 'offline',
        generated_at: new Date().toISOString(),
      });
    } finally {
      setIsQuerying(false);
    }
  };

  return (
    <section className="investigation-panel">
      <div className="demo-console">
        <div className="console-icon"><Shield size={18} /></div>
        <div className="console-copy">
          <span className="console-kicker">Live deception demo</span>
          <strong>Fake success, real containment</strong>
          <p>{demoMessage}</p>
        </div>
        <button className="primary-command" onClick={startLiveDemo} disabled={isDemoStarting} title="Run live attack demo">
          {isDemoStarting ? <Loader2 size={15} className="spin-icon" /> : <Play size={15} />}
          <span>{isDemoStarting ? 'Starting' : 'Run Attack'}</span>
        </button>
      </div>

      <div className="rag-console">
        <div className="rag-input-row">
          <div className="rag-input-wrap">
            <Search size={15} />
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter') void askRag(); }}
              placeholder="Ask: how many attempts from India?"
            />
          </div>
          <button className="query-command" onClick={() => void askRag()} disabled={isQuerying} title="Ask RAG">
            {isQuerying ? <Loader2 size={15} className="spin-icon" /> : <Database size={15} />}
          </button>
        </div>

        <div className="starter-row">
          {starterQueries.map((query) => (
            <button key={query} onClick={() => void askRag(query)}>{query}</button>
          ))}
        </div>

        <div className="rag-answer">
          {answer ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div className="rag-answer-text">{answer.answer}</div>
              
              {answer.evidence && answer.evidence.length > 0 && (
                <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: '0.06em' }}>
                    Incident Evidence Pointers ({answer.evidence.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto', paddingRight: 4 }}>
                    {answer.evidence.map((ev: any, i: number) => {
                      const riskColor = 
                        ev.risk_level === 'CRITICAL' ? 'var(--threat)' :
                        ev.risk_level === 'HIGH' ? 'var(--warn)' :
                        ev.risk_level === 'MEDIUM' ? 'var(--phantom)' : 'var(--muted)';
                        
                      return (
                        <div 
                          key={ev.alert_id || i} 
                          onClick={() => {
                            const fullAlert = alerts.find(a => a.alert_id === ev.alert_id);
                            if (fullAlert) {
                              onSelectAlert(fullAlert);
                            } else {
                              onSelectEntity(ev.entity_id);
                            }
                          }}
                          style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            background: '#0D1118', border: '1px solid var(--border)',
                            borderRadius: 8, padding: '7px 10px', cursor: 'pointer',
                            fontSize: 11
                          }}
                          className="evidence-item-hover"
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ 
                              background: riskColor + '1a', color: riskColor,
                              border: `1px solid ${riskColor}3d`, padding: '1px 5px',
                              borderRadius: 4, fontSize: 8, fontWeight: 800, fontFamily: 'var(--font-mono)' 
                            }}>
                              {ev.risk_level}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>
                              {ev.entity_id}
                            </span>
                            <span style={{ color: 'var(--border)' }}>•</span>
                            <span style={{ color: 'var(--muted)' }}>
                              {ev.attack_type?.replace('_', ' ')}
                            </span>
                          </div>
                          
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--muted)' }}>
                            <span>{ev.event?.geo_location || ev.geo_location}</span>
                            <span style={{ color: 'var(--drift)', fontWeight: 700 }}>Inspect →</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="rag-meta" style={{ marginTop: 4 }}>
                <span>{answer.pinecone_status}</span>
                <span>{answer.evidence.length} evidence records</span>
              </div>
            </div>
          ) : (
            <>
              <div className="rag-answer-text muted">Ask natural questions over alert, geo, attack, and Phantom action context.</div>
              <div className="rag-meta"><span>Pinecone-ready RAG</span><span>local fallback enabled</span></div>
            </>
          )}
        </div>
      </div>
    </section>
  );
};

