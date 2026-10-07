// 章ページ共通の手順エンジン（第1章以降で使う）
//   runSteps({steps:[{t,b,c,hl?}], all:{t,b,c}, tracks?})
//   t … 見出し / b … 本文HTML / c … コード行（HTML）/ hl … 光らせる手順番号（省略時は現在の手順）
//   onShow(cur, all, track) … 手順が変わるたびに呼ばれる（章ごとの追加の表示を戻すときなどに使う）
//   tracks … やり方が分かれる章では、手順を「線」に分ける。[{id, name, steps:[手順番号…]}]
//            同じ手順をいくつの線に入れてもよい（2本以上に入る手順は「共通」の印で表示する）
//            URL は #線の id-何番目（例 #pair-3）。#3 のような手順番号でも開ける
// 図の要素：data-step="n" は手順 n 以降ずっと表示、data-only="n m" はその手順のときだけ表示
window.code=s=>`<span class=c>${s}</span>`;
window.runSteps=function(cfg){
  const steps=cfg.steps;
  const $=id=>document.getElementById(id);
  const svg=$('svg'), dots=$('dots');
  const groups=[...svg.querySelectorAll('g[data-step]')], onlys=[...svg.querySelectorAll('g[data-only]')];
  const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
  // 線がない章は、全手順を1本の線として扱う
  const tracks=cfg.tracks||[{id:'',name:'',steps:steps.map((s,k)=>k+1)}];
  const multi=!!cfg.tracks;
  const uses=n=>tracks.filter(tr=>tr.steps.includes(n)).length;
  // 線を選んだときに始める位置：すべての線に共通する最初の部分は飛ばす
  tracks.forEach(tr=>{const k=tr.steps.findIndex(n=>uses(n)<tracks.length);tr.start=k<0?0:k});
  let t=0, p=0, all=false, paused=false;
  const cur=()=>tracks[t].steps[p];

  if(multi){
    dots.classList.add('lines');
    tracks.forEach((tr,ti)=>{
      const row=document.createElement('div');
      row.className='line';
      const name=document.createElement('button');
      name.className='lname'; name.textContent=tr.name;
      name.setAttribute('aria-label',`線「${tr.name}」を見る`);
      name.onclick=()=>{all=false;go(ti)};
      const stops=document.createElement('span');
      stops.className='stops';
      tr.steps.forEach((n,k)=>{
        const d=document.createElement('button');
        if(uses(n)>1)d.classList.add('shared');
        d.setAttribute('aria-label',`${tr.name} ${k+1}：${steps[n-1].t}${uses(n)>1?'（共通）':''}`);
        d.onclick=()=>{all=false;t=ti;p=k;show()};
        stops.appendChild(d);
      });
      row.append(name,stops);
      dots.appendChild(row);
    });
    const legend=document.createElement('div');
    legend.className='legend'; legend.textContent='○ はほかの線と共通の手順';
    dots.appendChild(legend);
  }else{
    steps.forEach((s,k)=>{
      const d=document.createElement('button');
      d.setAttribute('aria-label',`手順 ${k+1}：${s.t}`);
      d.onclick=()=>{all=false;p=k;show()};
      dots.appendChild(d);
    });
  }

  // 別の線へ移る。今の手順がその線の（共通の始まりより後に）あれば、そのまま線だけ替える
  function go(ti){
    const k=tracks[ti].steps.indexOf(cur());
    t=ti; p=k>=tracks[ti].start?k:tracks[ti].start; show();
  }
  // 線の終わりの次は、次の線の始め。最後の線の次は最初に戻る
  function step(d){
    const tr=tracks[t];
    if(p+d>=0&&p+d<tr.steps.length){p+=d}
    else if(d>0){t=(t+1)%tracks.length;p=t===0?0:tracks[t].start}
    else{t=(t-1+tracks.length)%tracks.length;p=tracks[t].steps.length-1}
    show();
  }

  function show(){
    const n=cur(), s=all?cfg.all:steps[n-1], hl=s.hl||[n], tr=tracks[t];
    svg.dataset.cur=all?'all':String(n);
    if(multi)svg.dataset.track=all?'all':tr.id;
    groups.forEach(g=>{
      const k=+g.dataset.step;
      g.classList.toggle('shown',all||k<=n);
      g.classList.toggle('now',!all&&hl.includes(k));
      g.classList.toggle('dim',!!(!all&&s.hl&&k<=n&&!hl.includes(k)));
    });
    onlys.forEach(g=>g.classList.toggle('shown',!all&&g.dataset.only.split(' ').includes(String(n))));
    $('count').textContent=all?'全体':multi?`${tr.name}　${p+1} / ${tr.steps.length}`:`${n} / ${steps.length}`;
    $('title').textContent=s.t;
    $('body').innerHTML=`<p>${s.b}</p>`;
    $('code').innerHTML=s.c.map(l=>`<span class="ln">${l}</span>`).join('');
    ['title','body','code'].forEach(id=>{const e=$(id);e.classList.remove('fade');void e.offsetWidth;e.classList.add('fade')});
    if(multi){
      [...dots.querySelectorAll('.line')].forEach((row,ti)=>{
        row.classList.toggle('on',!all&&ti===t);
        [...row.querySelector('.stops').children].forEach((d,k)=>d.classList.toggle('on',!all&&ti===t&&k===p));
      });
    }else{
      [...dots.children].forEach((d,k)=>d.classList.toggle('on',!all&&k===p));
    }
    $('all').setAttribute('aria-pressed',all);
    const h=all?'#all':multi?`#${tr.id}-${p+1}`:'#'+n;
    if(location.hash!==h)history.replaceState(null,'',h);
    if(cfg.onShow)cfg.onShow(n,all,multi?tr.id:undefined);
  }

  // #pair-3（線と位置）・#5（手順番号）・#all を読む
  function fromHash(){
    const h=location.hash;
    all=h==='#all';
    if(all)return show();
    const m=h.match(/^#([a-z0-9]+)-(\d+)$/);
    const ti=m?tracks.findIndex(tr=>tr.id===m[1]):-1;
    if(ti>=0){t=ti;p=Math.min(Math.max(+m[2]-1,0),tracks[ti].steps.length-1);return show()}
    const n=parseInt(h.slice(1),10);
    if(!isNaN(n)){
      const k=tracks.findIndex(tr=>tr.steps.includes(n));
      if(k>=0){t=k;p=tracks[k].steps.indexOf(n)}
    }
    show();
  }

  // 動きを減らす設定のときだけ止める（ボタンは置かない）
  function setPaused(v){
    paused=v;
    $('stage').classList.toggle('paused',v);
    v?svg.pauseAnimations():svg.unpauseAnimations();
  }

  $('prev').onclick=()=>{all=false;step(-1)};
  $('next').onclick=()=>{all=false;step(1)};
  $('all').onclick=()=>{all=!all;show()};
  addEventListener('keydown',e=>{
    if(e.ctrlKey||e.metaKey||e.altKey)return;
    if(e.key===' '&&e.target.closest('button,a,[role=button]'))return;
    if(['ArrowRight','PageDown',' '].includes(e.key)){e.preventDefault();all=false;step(1)}
    else if(['ArrowLeft','PageUp'].includes(e.key)){e.preventDefault();all=false;step(-1)}
    else if(multi&&(e.key==='ArrowDown'||e.key==='ArrowUp')){e.preventDefault();all=false;go((t+(e.key==='ArrowDown'?1:tracks.length-1))%tracks.length)}
    else if(e.key==='a'||e.key==='A'){all=!all;show()}
  });
  addEventListener('hashchange',fromHash);
  fromHash();
  if(reduce)setPaused(true);
};
