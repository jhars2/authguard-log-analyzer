#!/usr/bin/env python3
"""
AuthGuard Dashboard v3 — Flask Backend
"""

import sys
import os
import re
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string
import subprocess

app = Flask(__name__)

sys.path.insert(0, "/opt/authguard")
from log_analyzer import analyze_linux_logs


def run_analyzer():
    try:
        result = subprocess.run(
            [
                "journalctl", "--no-pager", "-o", "short",
                "--since", "7 days ago",
                "--grep", "sshd|sshd-session|sudo|Failed password|Accepted|Invalid user|pam_unix",
            ],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if not l.startswith("--")]
    except Exception as e:
        return [], str(e), 0, {}, [], [], []

    findings = analyze_linux_logs(lines=lines)

    # ── IP threat table ──
    ip_data = defaultdict(lambda: {"failed": 0, "users": set(), "severities": set(), "count": 0})
    ip_pattern = re.compile(r'from ([\d.:a-fA-F]+)')
    user_pattern = re.compile(r"'(\w+)'")
    for f in findings:
        m = ip_pattern.search(f.get("detail", ""))
        if m:
            ip = m.group(1)
            ip_data[ip]["severities"].add(f["severity"])
            ip_data[ip]["count"] += 1
            um = user_pattern.search(f["detail"])
            if um:
                ip_data[ip]["users"].add(um.group(1))

    ip_table = []
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for ip, d in ip_data.items():
        worst = next((s for s in sev_order if s in d["severities"]), "INFO")
        ip_table.append({"ip": ip, "severity": worst, "users": ", ".join(d["users"]) or "—", "count": d["count"]})
    ip_table.sort(key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 99)

    # ── User risk scoreboard ──
    user_risk = defaultdict(lambda: {"score": 0, "events": 0, "worst": "LOW", "types": set()})
    for f in findings:
        um = user_pattern.search(f.get("detail", ""))
        if um:
            u = um.group(1)
            score_map = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            user_risk[u]["score"] += score_map.get(f["severity"], 0)
            user_risk[u]["events"] += 1
            user_risk[u]["types"].add(f["detection"])
            cur = sev_order.index(user_risk[u]["worst"]) if user_risk[u]["worst"] in sev_order else 99
            new = sev_order.index(f["severity"]) if f["severity"] in sev_order else 99
            if new < cur:
                user_risk[u]["worst"] = f["severity"]

    user_table = sorted(
        [{"user": u, **d, "types": list(d["types"])[:2]} for u, d in user_risk.items()],
        key=lambda x: x["score"], reverse=True
    )[:8]

    # ── Hourly chart data ──
    hourly = defaultdict(int)
    ts_pat = re.compile(r'\w{3}\s+\d+\s(\d{2}):\d{2}:\d{2}')
    for f in findings:
        m = ts_pat.search(f.get("timestamp", ""))
        if m:
            hourly[int(m.group(1))] += 1
    hourly_data = [hourly.get(h, 0) for h in range(24)]

    # ── Detection type breakdown for donut ──
    detection_counts = defaultdict(int)
    for f in findings:
        detection_counts[f["detection"]] += 1
    donut_data = sorted(detection_counts.items(), key=lambda x: x[1], reverse=True)[:6]

    # ── Recent activity feed (last 15 findings chronologically) ──
    recent = list(reversed(findings[-15:]))

    return findings, None, len(lines), ip_table[:8], user_table, hourly_data, donut_data, recent


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuthGuard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@300;400;500;600;700&family=Barlow:wght@300;400;500;600&family=Source+Code+Pro:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
:root{
  --bg:#060606;
  --s1:#0c0c0c;
  --s2:#111;
  --s3:#181818;
  --border:rgba(255,255,255,0.055);
  --border2:rgba(255,255,255,0.1);
  --text:#efefef;
  --muted:#444;
  --muted2:#777;
  --crit:#ff3636;
  --high:#ff8800;
  --med:#3d8eff;
  --low:#00b86b;
  --font:'Barlow',sans-serif;
  --cond:'Barlow Condensed',sans-serif;
  --mono:'Source Code Pro',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;}

/* ── Topbar ── */
.topbar{height:50px;background:var(--s1);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:10;}
.tb-left{display:flex;align-items:center;gap:20px;}
.logo{font-family:var(--cond);font-size:20px;font-weight:700;letter-spacing:1px;color:var(--text);}
.tb-nav{display:flex;gap:4px;}
.tb-nav-item{font-family:var(--cond);font-size:13px;font-weight:500;letter-spacing:.5px;color:var(--muted2);padding:5px 12px;border-radius:3px;cursor:pointer;border:none;background:none;transition:all .12s;font-size:13px;}
.tb-nav-item:hover{color:var(--text);background:rgba(255,255,255,0.04);}
.tb-nav-item.on{color:var(--text);background:rgba(255,255,255,0.07);}
.tb-nav-item.f-crit.on{color:var(--crit);}
.tb-nav-item.f-high.on{color:var(--high);}
.tb-nav-item.f-med.on{color:var(--med);}
.tb-right{display:flex;align-items:center;gap:12px;}
.live-badge{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;letter-spacing:.5px;color:var(--muted2);}
.live-dot{width:6px;height:6px;border-radius:50%;background:#00b86b;animation:blink 2s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.tb-meta{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:.3px;}
.tb-btn{font-family:var(--cond);font-size:13px;font-weight:600;letter-spacing:.5px;padding:5px 14px;background:transparent;border:1px solid var(--border2);border-radius:3px;color:var(--text);cursor:pointer;transition:all .12s;text-decoration:none;}
.tb-btn:hover{background:rgba(255,255,255,0.06);}

/* ── Page layout ── */
.page{padding:20px 24px;display:flex;flex-direction:column;gap:16px;max-width:1600px;}

/* ── Stat row ── */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
.stat{background:var(--s1);border:1px solid var(--border);border-radius:4px;padding:20px 22px;}
.stat-lbl{font-family:var(--cond);font-size:16px;font-weight:500;letter-spacing:1.5px;color:var(--muted2);margin-bottom:6px;text-transform:uppercase;}
.stat-val{font-family:var(--cond);font-size:52px;font-weight:700;letter-spacing:-1px;line-height:1;color:var(--text);}

/* ── Grid layouts ── */
.row-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;}
.row-2{display:grid;grid-template-columns:2fr 1fr;gap:12px;}
.row-2b{display:grid;grid-template-columns:1fr 1fr;gap:12px;}

/* ── Section box ── */
.sec{background:var(--s1);border:1px solid var(--border);border-radius:4px;overflow:hidden;display:flex;flex-direction:column;}
.sec-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);flex-shrink:0;}
.sec-title{font-family:var(--cond);font-size:12px;font-weight:600;letter-spacing:1.5px;color:var(--muted2);text-transform:uppercase;}
.sec-meta{font-family:var(--mono);font-size:10px;color:var(--muted);}
.sec-body{flex:1;overflow:auto;}

/* ── Findings list ── */
.finding{display:grid;grid-template-columns:68px 1fr 14px;gap:10px;align-items:start;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;}
.finding:last-child{border-bottom:none;}
.finding:hover{background:rgba(255,255,255,.02);}
.finding.col .fd,.finding.col .ft{display:none;}
.finding.hide{display:none;}
.ft-title{font-size:12px;font-weight:500;margin-bottom:2px;color:var(--text);}
.fd{font-size:11px;color:var(--muted2);font-family:var(--mono);line-height:1.5;}
.ft{font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px;}
.chev{color:var(--muted);font-size:10px;transition:transform .15s;margin-top:2px;}
.finding.col .chev{transform:rotate(-90deg);}

/* ── Badge ── */
.badge{font-family:var(--mono);font-size:9px;font-weight:500;padding:2px 6px;border-radius:2px;letter-spacing:.5px;display:inline-block;}
.b-CRITICAL{background:rgba(255,54,54,.1);color:var(--crit);border:1px solid rgba(255,54,54,.2);}
.b-HIGH{background:rgba(255,136,0,.1);color:var(--high);border:1px solid rgba(255,136,0,.2);}
.b-MEDIUM{background:rgba(61,142,255,.1);color:var(--med);border:1px solid rgba(61,142,255,.2);}
.b-LOW{background:rgba(0,184,107,.1);color:var(--low);border:1px solid rgba(0,184,107,.2);}

/* ── Table shared ── */
.data-table{width:100%;border-collapse:collapse;}
.data-table th{font-family:var(--cond);font-size:10px;font-weight:600;letter-spacing:1.2px;color:var(--muted);padding:9px 16px;text-align:left;border-bottom:1px solid var(--border);text-transform:uppercase;}
.data-table td{font-size:11px;font-family:var(--mono);padding:9px 16px;border-bottom:1px solid var(--border);color:var(--muted2);}
.data-table tr:last-child td{border-bottom:none;}
.data-table tr:hover td{background:rgba(255,255,255,.02);}
.td-main{color:var(--text);font-weight:500;}

/* ── Risk score bar ── */
.risk-bar-wrap{display:flex;align-items:center;gap:8px;}
.risk-bar{height:3px;background:var(--border2);border-radius:2px;flex:1;max-width:60px;}
.risk-fill{height:100%;border-radius:2px;background:var(--muted2);}
.risk-fill.crit{background:var(--crit);}
.risk-fill.hi{background:var(--high);}
.risk-fill.med{background:var(--med);}
.risk-num{font-family:var(--mono);font-size:10px;color:var(--muted2);min-width:20px;}

/* ── Activity feed ── */
.feed-item{display:flex;align-items:flex-start;gap:10px;padding:9px 16px;border-bottom:1px solid var(--border);}
.feed-item:last-child{border-bottom:none;}
.feed-dot{width:6px;height:6px;border-radius:50%;margin-top:4px;flex-shrink:0;}
.feed-dot.CRITICAL{background:var(--crit);}
.feed-dot.HIGH{background:var(--high);}
.feed-dot.MEDIUM{background:var(--med);}
.feed-dot.LOW{background:var(--low);}
.feed-body{flex:1;min-width:0;}
.feed-title{font-size:11px;font-weight:500;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.feed-detail{font-size:10px;color:var(--muted2);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.feed-time{font-family:var(--mono);font-size:10px;color:var(--muted);flex-shrink:0;margin-top:1px;}

/* ── Chart ── */
.chart-wrap{padding:14px 16px;}

/* ── Empty ── */
.empty{padding:30px 16px;text-align:center;font-family:var(--mono);font-size:11px;color:var(--muted);}

::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px;}
</style>
</head>
<body>

<!-- Topbar -->
<div class="topbar">
  <div class="tb-left">
    <span class="logo">AUTHGUARD</span>
    <nav class="tb-nav">
      <button class="tb-nav-item on" onclick="filter('all',this)">All <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">{{ total }}</span></button>
      <button class="tb-nav-item f-crit" onclick="filter('CRITICAL',this)">Critical <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">{{ critical }}</span></button>
      <button class="tb-nav-item f-high" onclick="filter('HIGH',this)">High <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">{{ high }}</span></button>
      <button class="tb-nav-item f-med" onclick="filter('MEDIUM',this)">Medium <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">{{ medium }}</span></button>
    </nav>
  </div>
  <div class="tb-right">
    <div class="live-badge"><span class="live-dot"></span>LIVE</div>
    <span class="tb-meta" id="cd"></span>
    <span class="tb-meta">{{ scan_time }}</span>
    <a href="/" class="tb-btn">↻ REFRESH</a>
  </div>
</div>

<!-- Page -->
<div class="page">

  <!-- Stat row -->
  <div class="stat-row">
    <div class="stat"><div class="stat-lbl">Total Findings</div><div class="stat-val">{{ total }}</div></div>
    <div class="stat"><div class="stat-lbl">Critical</div><div class="stat-val">{{ critical }}</div></div>
    <div class="stat"><div class="stat-lbl">High</div><div class="stat-val">{{ high }}</div></div>
    <div class="stat"><div class="stat-lbl">Medium</div><div class="stat-val">{{ medium }}</div></div>
  </div>

  <!-- Row: Findings (wide) + Activity Feed -->
  <div class="row-2">
    <div class="sec" style="max-height:420px;">
      <div class="sec-head">
        <span class="sec-title">Findings</span>
        <span class="sec-meta" id="vc">{{ total }} shown</span>
      </div>
      <div class="sec-body">
        {% if findings %}
          {% for f in findings %}
          <div class="finding" data-sev="{{ f.severity }}" onclick="toggle(this)">
            <span class="badge b-{{ f.severity }}">{{ f.severity }}</span>
            <div>
              <div class="ft-title">{{ f.detection }}</div>
              <div class="fd">{{ f.detail }}</div>
              <div class="ft">{{ f.timestamp }}</div>
            </div>
            <span class="chev">⌄</span>
          </div>
          {% endfor %}
        {% else %}
          <div class="empty">No findings in the last 7 days.</div>
        {% endif %}
      </div>
    </div>

    <!-- Activity Feed -->
    <div class="sec" style="max-height:420px;">
      <div class="sec-head">
        <span class="sec-title">Recent Activity</span>
        <span class="sec-meta">Latest {{ recent|length }} events</span>
      </div>
      <div class="sec-body">
        {% if recent %}
          {% for f in recent %}
          <div class="feed-item">
            <span class="feed-dot {{ f.severity }}"></span>
            <div class="feed-body">
              <div class="feed-title">{{ f.detection }}</div>
              <div class="feed-detail">{{ f.detail }}</div>
            </div>
            <span class="feed-time">{{ f.timestamp }}</span>
          </div>
          {% endfor %}
        {% else %}
          <div class="empty">No recent activity.</div>
        {% endif %}
      </div>
    </div>
  </div>

  <!-- Row: Attack timeline + Donut chart -->
  <div class="row-2b">
    <div class="sec">
      <div class="sec-head">
        <span class="sec-title">Attack Timeline</span>
        <span class="sec-meta">Findings by hour — 24h window</span>
      </div>
      <div class="chart-wrap">
        <div style="position:relative;height:180px;">
          <canvas id="tc" role="img" aria-label="Bar chart of security findings by hour of day"></canvas>
        </div>
      </div>
    </div>

    <div class="sec">
      <div class="sec-head">
        <span class="sec-title">Detection Breakdown</span>
        <span class="sec-meta">By type</span>
      </div>
      <div class="chart-wrap" style="display:flex;align-items:center;gap:20px;">
        <div style="position:relative;width:140px;height:140px;flex-shrink:0;">
          <canvas id="dc" role="img" aria-label="Donut chart of findings by detection type"></canvas>
        </div>
        <div id="donut-legend" style="display:flex;flex-direction:column;gap:7px;flex:1;min-width:0;"></div>
      </div>
    </div>
  </div>

  <!-- Row: IP Threat Table + User Risk Scoreboard -->
  <div class="row-2b">
    <div class="sec">
      <div class="sec-head">
        <span class="sec-title">Threat IP Sources</span>
        <span class="sec-meta">{{ ip_table|length }} unique IPs</span>
      </div>
      <div class="sec-body">
        {% if ip_table %}
        <table class="data-table">
          <thead><tr><th>IP Address</th><th>Severity</th><th>Events</th><th>Targets</th></tr></thead>
          <tbody>
            {% for row in ip_table %}
            <tr>
              <td class="td-main">{{ row.ip }}</td>
              <td><span class="badge b-{{ row.severity }}">{{ row.severity }}</span></td>
              <td>{{ row.count }}</td>
              <td>{{ row.users }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% else %}<div class="empty">No IP data available.</div>{% endif %}
      </div>
    </div>

    <div class="sec">
      <div class="sec-head">
        <span class="sec-title">User Risk Scoreboard</span>
        <span class="sec-meta">By calculated risk score</span>
      </div>
      <div class="sec-body">
        {% if user_table %}
        <table class="data-table">
          <thead><tr><th>Account</th><th>Risk</th><th>Severity</th><th>Events</th></tr></thead>
          <tbody>
            {% for row in user_table %}
            <tr>
              <td class="td-main">{{ row.user }}</td>
              <td>
                <div class="risk-bar-wrap">
                  <div class="risk-bar">
                    <div class="risk-fill {% if row.worst == 'CRITICAL' %}crit{% elif row.worst == 'HIGH' %}hi{% elif row.worst == 'MEDIUM' %}med{% endif %}"
                         style="width:{{ [row.score * 5, 100]|min }}%"></div>
                  </div>
                  <span class="risk-num">{{ row.score }}</span>
                </div>
              </td>
              <td><span class="badge b-{{ row.worst }}">{{ row.worst }}</span></td>
              <td>{{ row.events }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% else %}<div class="empty">No user data available.</div>{% endif %}
      </div>
    </div>
  </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
var hourly = {{ hourly_data | tojson }};
var donutRaw = {{ donut_data | tojson }};
var monoFont = "Source Code Pro, monospace";
var donutColors = ["#ff3636","#ff8800","#3d8eff","#00b86b","#a78bfa","#f472b6"];

new Chart(document.getElementById("tc"), {
  type: "bar",
  data: {
    labels: ["00h","01h","02h","03h","04h","05h","06h","07h","08h","09h","10h","11h","12h","13h","14h","15h","16h","17h","18h","19h","20h","21h","22h","23h"],
    datasets:[{
      data: hourly,
      backgroundColor: hourly.map(function(v){ return v===0 ? "rgba(255,255,255,0.04)" : v>=5 ? "rgba(255,54,54,0.65)" : "rgba(255,136,0,0.5)"; }),
      borderRadius: 2,
      borderSkipped: false
    }]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:"#111",
        borderColor:"rgba(255,255,255,0.08)",
        borderWidth:1,
        titleColor:"#efefef",
        bodyColor:"#777",
        titleFont:{family:monoFont,size:10},
        bodyFont:{family:monoFont,size:10},
        callbacks:{
          title:function(i){return i[0].label;},
          body:function(i){return i[0].raw+" findings";}
        }
      }
    },
    scales:{
      x:{grid:{color:"rgba(255,255,255,0.04)"},ticks:{color:"#444",font:{family:monoFont,size:9},maxRotation:0}},
      y:{grid:{color:"rgba(255,255,255,0.04)"},ticks:{color:"#444",font:{family:monoFont,size:9},stepSize:1},beginAtZero:true}
    }
  }
});

var donutLabels = donutRaw.map(function(d){return d[0];});
var donutVals   = donutRaw.map(function(d){return d[1];});

new Chart(document.getElementById("dc"), {
  type:"doughnut",
  data:{
    labels: donutLabels,
    datasets:[{data:donutVals, backgroundColor:donutColors, borderWidth:0, hoverOffset:4}]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    cutout:"68%",
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:"#111",
        borderColor:"rgba(255,255,255,0.08)",
        borderWidth:1,
        titleColor:"#efefef",
        bodyColor:"#777",
        titleFont:{family:monoFont,size:10},
        bodyFont:{family:monoFont,size:10}
      }
    }
  }
});

var leg = document.getElementById("donut-legend");
var total = donutVals.reduce(function(a,b){return a+b;}, 0);
for(var i=0; i<donutLabels.length; i++){
  var pct = total > 0 ? Math.round(donutVals[i]/total*100) : 0;
  var label = donutLabels[i].length > 22 ? donutLabels[i].slice(0,20)+"..." : donutLabels[i];
  var div = document.createElement("div");
  div.style.cssText = "display:flex;align-items:center;gap:7px;font-size:10px;color:#777;font-family:"+monoFont+";";
  div.innerHTML = "<span style='width:8px;height:8px;border-radius:2px;background:"+donutColors[i]+";flex-shrink:0;'></span>"
    + "<span style='flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;'>"+label+"</span>"
    + "<span style='color:#efefef;font-weight:500;'>"+pct+"%</span>";
  leg.appendChild(div);
}

function filter(sev, btn){
  document.querySelectorAll(".tb-nav-item").forEach(function(b){b.classList.remove("on");});
  btn.classList.add("on");
  var v=0;
  document.querySelectorAll(".finding").forEach(function(f){
    var show = sev==="all" || f.dataset.sev===sev;
    f.classList.toggle("hide",!show);
    if(show) v++;
  });
  document.getElementById("vc").textContent = v+" shown";
}

function toggle(el){ el.classList.toggle("col"); }

var s=60;
var cd=document.getElementById("cd");
function tick(){
  s--;
  if(s<=0){ location.reload(); }
  else{ cd.textContent="refreshing in "+s+"s"; setTimeout(tick,1000); }
}
setTimeout(tick,1000);
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    findings, error, log_count, ip_table, user_table, hourly_data, donut_data, recent = run_analyzer()

    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    findings.sort(key=lambda f: order.get(f["severity"],99))

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    return render_template_string(
        DASHBOARD_HTML,
        findings=findings,
        total=len(findings),
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M"),
        log_entries=log_count,
        ip_table=ip_table,
        user_table=user_table,
        hourly_data=hourly_data,
        donut_data=donut_data,
        recent=recent,
        error=error
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
