// ページ間ナビ：<nav class="sitenav" data-page="docs/01-objects.html" data-root="../"> に「前／目次／次」を入れる
// 章とリファレンスの並びはここで管理する（index.html の一覧も合わせて更新すること）
(function(){
  const CHAPTERS=[
    ['docs/00-overview.html','第0章 全体像'],
    ['docs/01-objects.html','第1章 オブジェクトと属性'],
    ['docs/02-keypair.html','第2章 鍵ペアの生成'],
  ];
  const REFS=[
    ['docs/ref-attributes.html','属性リファレンス'],
  ];
  document.querySelectorAll('nav.sitenav').forEach(n=>{
    const root=n.dataset.root||'', me=n.dataset.page;
    const list=CHAPTERS.some(c=>c[0]===me)?CHAPTERS:REFS;
    const k=list.findIndex(c=>c[0]===me), prev=list[k-1], next=list[k+1];
    const link=(x,cls,text)=>x?`<a class="${cls}" href="${root}${x[0]}">${text}</a>`:`<span class="${cls} off">${text}</span>`;
    const kind=list===CHAPTERS?'章':'リファレンス';
    n.innerHTML=link(prev,'prev',prev?`← ${prev[1]}`:`← 前の${kind}はなし`)
      +`<a class="home" href="${root}index.html">目次へ戻る</a>`
      +link(next,'next',next?`${next[1]} →`:`次の${kind}は準備中 →`);
  });
})();
