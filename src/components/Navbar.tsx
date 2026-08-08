import React from 'react';
import { Shield, Activity, Terminal, Cpu, LayoutDashboard, Code, BookOpen } from 'lucide-react';

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
    { id: 'queue', label: 'SIEM Queue', icon: LayoutDashboard, badge: alertCount },
    { id: 'intel', label: 'Threat Intel & ATT&CK', icon: Activity },
    { id: 'rules', label: 'Detection Rule Studio', icon: Code },
    { id: 'portfolio', label: 'Portfolio & Export', icon: BookOpen, highlight: true },
  ];

  return (
    <header className="bg-slate-950/95 backdrop-blur-md border-b border-slate-800 text-slate-100 sticky top-0 z-50 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Brand Logo & Name */}
          <div 
            className="flex items-center space-x-3 cursor-pointer shrink-0 group"
            onClick={() => setActiveTab('triage')}
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/40 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-base tracking-tight text-white group-hover:text-cyan-400 transition-colors">
                  AegisThreat <span className="text-cyan-400 font-mono">AI</span>
                </span>
                <span className="bg-cyan-950/90 border border-cyan-600/50 text-cyan-300 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider hidden sm:inline-block">
                  v2.0
                </span>
              </div>
              <span className="text-[11px] text-slate-400 font-medium leading-tight hidden sm:block">
                Threat Intelligence & DFIR Copilot
              </span>
            </div>
          </div>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center space-x-1 lg:space-x-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950'
                      : item.highlight
                      ? 'bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white border border-slate-800'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span className="whitespace-nowrap">{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1 bg-rose-500 text-white text-[10px] font-bold px-1.5 py-0.2 rounded-full">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Status Badge */}
          <div className="flex items-center space-x-2 shrink-0">
            <div
              className={`flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border ${
                geminiActive
                  ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300'
                  : 'bg-amber-950/60 border-amber-500/40 text-amber-300'
              }`}
              title={geminiActive ? 'Google Gemini 2.5 API Active' : 'Deterministic Rule Engine Active'}
            >
              <Cpu className={`w-3.5 h-3.5 ${geminiActive ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
              <span className="whitespace-nowrap">
                {geminiActive ? 'Gemini 2.5 AI' : 'Deterministic Mode'}
              </span>
            </div>
          </div>

        </div>
      </div>

      {/* Mobile Bar */}
      <div className="md:hidden flex overflow-x-auto border-t border-slate-800 bg-slate-900/90 px-3 py-2 space-x-1.5 no-scrollbar">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap ${
                isActive ? 'bg-cyan-950 text-cyan-300 border border-cyan-600/50' : 'text-slate-400 hover:bg-slate-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{item.label}</span>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="bg-rose-500 text-white text-[10px] font-bold px-1 rounded-full">
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
