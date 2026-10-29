() => {
    const canary = "__CANARY__";
    const hits   = [];
    let seen     = 0;
    let foundDangerous = false;

    const walker = document.createTreeWalker(
        document.documentElement,
        0x1 | 0x4 | 0x80
    );
    let node;
    while ((node = walker.nextNode()) && seen++ < __MAX_WALK__) {
        if (foundDangerous) break;
        if (node.nodeType === 3 && node.textContent.includes(canary) && !/^(SCRIPT|STYLE)$/.test(node.parentElement?.tagName || ''))
            hits.push({context:'html_text', parent: node.parentElement?.tagName||'', parent_id: node.parentElement?.id||'', parent_class: (node.parentElement?.className && typeof node.parentElement.className === 'string') ? node.parentElement.className.slice(0,60) : ''});
        if (node.nodeType === 8 && node.textContent.includes(canary))
            hits.push({context:'html_comment'});
        if (node.nodeType === 1) {
            for (const attr of (node.attributes || [])) {
                if (!attr.value.includes(canary)) continue;
                const risk = /^on[a-z]/i.test(attr.name) ? 'event_handler'
                    : /^(href|src|action|formaction|xlink:href|data|poster|cite|codebase|icon)$/i.test(attr.name) ? 'url_attr'
                    : 'generic_attr';
                hits.push({context:'html_attribute', attr:attr.name, element:node.tagName, risk});
                if (risk === 'event_handler') foundDangerous = true;
            }
        }
    }

    document.querySelectorAll('script:not([src])').forEach(s => {
        if (!s.textContent.includes(canary)) return;
        const stype = (s.type || '').toLowerCase();
        if (stype && stype !== 'text/javascript' && stype !== 'module') return;
        const sid = s.id || '';
        if (/^__NEXT_DATA__|__NEXT_LOADED|__NUXT_STATE__|__NUXT__|__REDUX_STATE__|__APOLLO_STATE__|__RELAY_STORE__|__INITIAL_STATE__/.test(sid)) return;
        const txt = s.textContent.trim();
        if (txt[0] === '{' || txt[0] === '[') {
            try { JSON.parse(txt); return; } catch(_) {}
        }
        hits.push({context:'script_block', dangerous:true});
    });

    try { if (localStorage.getItem('canary') === canary)  hits.push({context:'localStorage'}); } catch(e) {}
    try { if (sessionStorage.getItem('canary') === canary) hits.push({context:'sessionStorage'}); } catch(e) {}
    try { if (document.cookie.includes(canary)) hits.push({context:'cookie'}); } catch(e) {}
    try { if (window.name === canary) hits.push({context:'window_name'}); } catch(e) {}

    (window.__sinkHits || []).filter(h => !/UtilityScript/.test(h.stack || '')).forEach(h => {
        hits.push({context:'sink_'+h.sink, sink:h.sink || '', value:(h.snippet || '').slice(0,100), category:h.category || '', target:h.target || '', stack:(h.stack || '').slice(0,300)});
    });

    // Inspect accessible open shadow roots recursively. Closed roots
    // cannot be traversed from page JavaScript; their creation is only counted.
    const roots = [document];
    const closedMap = new Map((window.__closedRoots || []).filter(r => r.host.isConnected).map(r => [r.host, r.root]));
    const visitedRoots = new Set();
    while (roots.length) {
        const root = roots.pop();
        if (!root || visitedRoots.has(root)) continue;
        visitedRoots.add(root);
        let descendants = [];
        try { descendants = root.querySelectorAll('*'); } catch(e) {}
        descendants.forEach(el => {
            try {
                const sr = el.shadowRoot || closedMap.get(el);
                if (sr) {
                    if (sr.innerHTML.includes(canary))
                        hits.push({context:'shadow_dom', element:el.tagName, mode: el.shadowRoot ? 'open' : 'closed'});
                    roots.push(sr);
                }
            } catch(e) {}
        });
    }

    return hits;
}
