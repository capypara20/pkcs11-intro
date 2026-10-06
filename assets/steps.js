// 章ページ共通の手順エンジン（第1章以降で使う）
//   runSteps({steps:[{t,b,c,hl?}], all:{t,b,c}})
//   t … 見出し / b … 本文HTML / c … コード行（HTML）/ hl … 光らせる手順番号（省略時は現在の手順）
//   onShow(cur, all) … 手順が変わるたびに呼ばれる（章ごとの追加の表示を戻すときなどに使う）
// 図の要素：data-step="n" は手順 n 以降ずっと表示、data-only="n m" はその手順のときだけ表示
window.code=s=>`<span class=c>${s}</span>`;
window.runSteps=function(cfg){
  const steps=cfg.steps;
  const $=id=>document.getElementById(id);
  const svg=$('svg'), dots=$('dots');
  const groups=[...svg.querySelectorAll('g[data-step]')], onlys=[...svg.querySelectorAll('g[data-only]')];
  const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
  let i=0, all=false, paused=false;

  steps.forEach((s,k)=>{
    const d=document.createElement('button');
    d.setAttribute('aria-label',`手順 ${k+1}：${s.t}`);
    d.onclick=()=>{all=false;show(k)};
    dots.appendChild(d);
  });

  function fit(){document.documentElement.style.setProperty('--s',Math.min(innerWidth/1280,innerHeight/720))}

  function show(n){
    i=Math.max(0,Math.min(steps.length-1,n));
    const s=all?cfg.all:steps[i], cur=i+1, hl=s.hl||[cur];
    svg.dataset.cur=all?'all':String(cur);
    groups.forEach(g=>{
      const k=+g.dataset.step;
      g.classList.toggle('shown',all||k<=cur);
      g.classList.toggle('now',!all&&hl.includes(k));
      g.classList.toggle('dim',!!(!all&&s.hl&&k<=cur&&!hl.includes(k)));
    });
    onlys.forEach(g=>g.classList.toggle('shown',!all&&g.dataset.only.split(' ').includes(String(cur))));
    $('count').textContent=all?'全体':`${cur} / ${steps.length}`;
    $('title').textContent=s.t;
    $('body').innerHTML=`<p>${s.b}</p>`;
    $('code').innerHTML=s.c.map(l=>`<span class="ln">${l}</span>`).join('');
    ['title','body','code'].forEach(id=>{const e=$(id);e.classList.remove('fade');void e.offsetWidth;e.classList.add('fade')});
    [...dots.children].forEach((d,k)=>d.classList.toggle('on',!all&&k===i));
    $('all').setAttribute('aria-pressed',all);
    const h=all?'#all':'#'+cur;
    if(location.hash!==h)history.replaceState(null,'',h);
    if(cfg.onShow)cfg.onShow(cur,all);
  }

  function setPaused(p){
    paused=p;
    $('stage').classList.toggle('paused',p);
    p?svg.pauseAnimations():svg.unpauseAnimations();
    $('pause').setAttribute('aria-pressed',p);
    $('pause').textContent=p?'再生':'一時停止';
  }

  $('prev').onclick=()=>{all=false;show(i-1)};
  $('next').onclick=()=>{all=false;show(i+1)};
  $('all').onclick=()=>{all=!all;show(i)};
  $('pause').onclick=()=>setPaused(!paused);
  $('theme').onclick=()=>toggleTheme();
  addEventListener('keydown',e=>{
    if(e.ctrlKey||e.metaKey||e.altKey)return;
    if(e.key===' '&&e.target.closest('button,a,[role=button]'))return;
    if(['ArrowRight','PageDown',' '].includes(e.key)){e.preventDefault();all=false;show(i+1)}
    else if(['ArrowLeft','PageUp'].includes(e.key)){e.preventDefault();all=false;show(i-1)}
    else if(e.key==='a'||e.key==='A'){all=!all;show(i)}
    else if(e.key==='p'||e.key==='P')setPaused(!paused);
    else if(e.key==='t'||e.key==='T')toggleTheme();
  });
  addEventListener('resize',fit);
  addEventListener('hashchange',()=>{all=location.hash==='#all';const m=parseInt(location.hash.slice(1),10);show(isNaN(m)?i:m-1)});
  if(location.hash==='#all')all=true;
  const n=parseInt(location.hash.slice(1),10);
  fit();show(isNaN(n)?0:n-1);
  if(reduce)setPaused(true);
};
