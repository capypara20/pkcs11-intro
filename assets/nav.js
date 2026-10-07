// ページ間ナビ：<nav class="sitenav" data-page="docs/01-objects.html" data-root="../"> に「前／目次／次」を入れる
// 章とリファレンスの並びはここで管理する（index.html の一覧も合わせて更新すること）
(function(){
  const CHAPTERS=[
    ['docs/00-overview.html','第0章 全体像'],
    ['docs/01-objects.html','第1章 オブジェクトと属性'],
    ['docs/02-keygen.html','第2章 鍵の生成'],
    ['docs/03-sign.html','第3章 署名と検証'],
    ['docs/04-crypt.html','第4章 暗号化と復号'],
    ['docs/05-errors.html','第5章 エラーコード'],
    ['docs/06-init.html','第6章 初期化とセッション'],
  ];
  const REFS=[
    ['docs/ref-attributes.html','属性リファレンス'],
  ];
  // 根拠にしている OASIS の仕様書（新しいタブで開く）。index.html の参考資料も合わせて更新すること
  const SPEC={
    base:['https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html','Base v2.40'],
    curr:['https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html','Mechanisms v2.40'],
    latest:['https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html','最新 v3.2'],
  };
  document.querySelectorAll('nav.sitenav').forEach(n=>{
    const root=n.dataset.root||'', me=n.dataset.page;
    const list=CHAPTERS.some(c=>c[0]===me)?CHAPTERS:REFS;
    const k=list.findIndex(c=>c[0]===me), prev=list[k-1], next=list[k+1];
    const link=(x,cls,text)=>x?`<a class="${cls}" href="${root}${x[0]}">${text}</a>`:`<span class="${cls} off">${text}</span>`;
    const kind=list===CHAPTERS?'章':'リファレンス';
    // data-spec="base curr latest" のように、そのページの根拠になる仕様書を並べる
    const spec=(n.dataset.spec||'base latest').split(' ').map(s=>`<a href="${SPEC[s][0]}" target="_blank" rel="noopener">${SPEC[s][1]}</a>`).join(' ／ ');
    n.innerHTML=link(prev,'prev',prev?`← ${prev[1]}`:`← 前の${kind}はなし`)
      +`<span class="mid"><a class="home" href="${root}index.html">目次へ戻る</a><span class="spec">仕様書（OASIS）：${spec}</span></span>`
      +link(next,'next',next?`${next[1]} →`:`次の${kind}は準備中 →`);
  });
})();
