import React from 'react';
import { Shield, Activity, Terminal, Cpu, Database, FileText, LayoutDashboard, Code, BookOpen, AlertCircle } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  alertCount: number;
  geminiActive: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  alertCount,
  geminiActive,
}) => {
  const navItems = [
    { id: 'triage', label: 'Log Triage & AI Parser', icon: Terminal },
    { id: 'queue', label: 'SIEM Alert Queue', icon: LayoutDashboard, badge: alertCount },
    { id: 'intel', label: 'ATT&CK & Threat Intel', icon: Activity },
    { id: 'rules', label: 'AI Rule Studio', icon: Code },
    { id: 'portfolio', label: 'Portfolio & GitHub Export', icon: BookOpen, highlight: true },
  ];

  return (
    <header className="bg-slate-950 border-b border-slate-800 text-slate-100 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Platform Name */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('triage')}>
            <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-wide text-white">SOC Sentinel</span>
                <span className="bg-cyan-950 border border-cyan-700/60 text-cyan-400 text-xs font-semibold px-2 py-0.5 rounded-full uppercase tracking-wider">
                  AI Copilot
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">Threat Intelligence & DFIR Triage Platform</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex space-x-1 lg:space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-cyan-500/40 shadow-sm'
                      : item.highlight
                      ? 'bg-cyan-950/40 text-cyan-300 hover:bg-slate-800 border border-cyan-800/50'
                      : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1 bg-rose-600 text-white text-xs font-bold px-1.5 py-0.2 rounded-full">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* System Status Indicators */}
          <div className="flex items-center space-x-3">
            <div className="hidden lg:flex items-center space-x-2 bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-slate-300">SIEM Stream Active</span>
            </div>

            <div
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs border font-mono ${
                geminiActive
                  ? 'bg-emerald-950/50 border-emerald-700/50 text-emerald-400'
                  : 'bg-amber-950/50 border-amber-700/50 text-amber-400'
              }`}
              title={geminiActive ? 'Google Gemini 3.6 Flash Active' : 'Offline Analytical Mode (Add API Key in Secrets)'}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{geminiActive ? 'Gemini 3.6 API' : 'Deterministic Mode'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile Navigation Row */}
      <div className="md:hidden flex overflow-x-auto border-t border-slate-800 bg-slate-900 p-2 space-x-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap ${
                isActive ? 'bg-slate-800 text-cyan-400 border border-cyan-500/40' : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{item.label}</span>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="bg-rose-600 text-white text-[10px] font-bold px-1 rounded-full">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};
