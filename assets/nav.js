// ページ間ナビ：<nav class="sitenav" data-page="docs/03-objects.html" data-root="../"> に「前／目次／次」を入れる
// 章・シナリオ・リファレンスの並びはここで管理する（index.html の一覧も合わせて更新すること）
(function(){
  const CHAPTERS=[
    ['docs/00-overview.html','第0章 全体像'],
    ['docs/01-init.html','第1章 初期化'],
    ['docs/02-connect.html','第2章 アプリからつなぐ'],
    ['docs/03-objects.html','第3章 オブジェクトと属性'],
    ['docs/04-keygen.html','第4章 鍵の生成'],
    ['docs/05-find.html','第5章 鍵の探し方と名前の付け方'],
    ['docs/06-crypt.html','第6章 暗号化と復号'],
    ['docs/07-sign.html','第7章 署名と検証'],
  ];
  // 1本の鍵を最初から最後まで追う、章をまたいだ通しの例
  const SCENARIOS=[
    ['docs/s1-lifecycle.html','シナリオ1 鍵の一生'],
  ];
  const REFS=[
    ['docs/ref-attributes.html','属性リファレンス'],
    ['docs/ref-mechanisms.html','メカニズムリファレンス'],
    ['docs/ref-functions.html','関数リファレンス'],
    ['docs/ref-maintenance.html','メンテナンス API リファレンス'],
    ['docs/ref-errors.html','エラーコードリファレンス'],
    ['docs/ref-commands.html','コマンドリファレンス'],
  ];
  // 根拠にしている OASIS の仕様書（新しいタブで開く）。index.html の参考資料も合わせて更新すること
  const SPEC={
    base:['https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html','Base v2.40'],
    curr:['https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html','Mechanisms v2.40'],
    latest:['https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html','最新 v3.2'],
  };
  document.querySelectorAll('nav.sitenav').forEach(n=>{
    const root=n.dataset.root||'', me=n.dataset.page;
    const list=[CHAPTERS,SCENARIOS,REFS].find(l=>l.some(c=>c[0]===me))||REFS;
    const k=list.findIndex(c=>c[0]===me), prev=list[k-1], next=list[k+1];
    const link=(x,cls,text)=>x?`<a class="${cls}" href="${root}${x[0]}">${text}</a>`:`<span class="${cls} off">${text}</span>`;
    const kind=list===CHAPTERS?'章':list===SCENARIOS?'シナリオ':'リファレンス';
    // data-spec="base curr latest" のように、そのページの根拠になる仕様書を並べる
    const spec=(n.dataset.spec||'base latest').split(' ').map(s=>`<a href="${SPEC[s][0]}" target="_blank" rel="noopener">${SPEC[s][1]}</a>`).join(' ／ ');
    n.innerHTML=link(prev,'prev',prev?`← ${prev[1]}`:`← 前の${kind}はなし`)
      +`<span class="mid"><a class="home" href="${root}index.html">目次へ戻る</a><span class="spec">仕様書（OASIS）：${spec}</span></span>`
      +link(next,'next',next?`${next[1]} →`:`次の${kind}は準備中 →`);
  });
})();
