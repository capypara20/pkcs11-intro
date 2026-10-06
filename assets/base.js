// テーマ切替（全章共通）。保存できない環境でも動くように try で囲む
(function(){
  const r=document.documentElement;
  try{const t=localStorage.getItem('pkcs11-theme');if(t)r.dataset.theme=t}catch(e){}
  window.toggleTheme=function(){
    const cur=r.dataset.theme||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
    const n=cur==='light'?'dark':'light';
    r.dataset.theme=n;
    try{localStorage.setItem('pkcs11-theme',n)}catch(e){}
  };
})();
