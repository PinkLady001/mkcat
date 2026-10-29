(() => {
    'use strict';

    const _shadowLog  = [];
    const _sinkHits   = [];
    const _closedRoots = [];
    Object.defineProperty(window, '__closedRoots', { value: _closedRoots, enumerable: false, configurable: true });
    window.__sinkHits = _sinkHits;

    // Track addEventListener registrations by event type. Powers the bounded,
    // opt-in interaction stage (trigger_interactions() in the Python driver):
    // a sink inside a click/hover handler never fires during passive
    // navigation, so it is otherwise invisible to this scanner.
    try {
        const _listenersByType = Object.create(null);
        window.__listenersByType = _listenersByType;
        const _origAddEventListener = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            try {
                if (this instanceof Element) {
                    const t = String(type);
                    if (!_listenersByType[t]) _listenersByType[t] = new Set();
                    _listenersByType[t].add(this);
                }
            } catch(e) {}
            return _origAddEventListener.call(this, type, listener, options);
        };
    } catch(e) {}

    const _SINK_CATEGORIES = {
        'eval': 'code_exec', 'Function': 'code_exec',
        'setTimeout': 'code_exec', 'setInterval': 'code_exec',
        'setAttribute': 'attr_injection',
        'innerHTML': 'html_injection', 'outerHTML': 'html_injection',
        'insertAdjacentHTML': 'html_injection', 'document.write': 'html_injection',
        'srcdoc': 'html_injection', 'createContextualFragment': 'html_injection',
        'DOMParser.parseFromString': 'html_injection',
        'setHTMLUnsafe': 'html_injection', 'ShadowRoot.setHTML': 'html_injection',
        'append': 'dom_propagation', 'prepend': 'dom_propagation',
        'replaceChildren': 'dom_propagation', 'replaceWith': 'dom_propagation',
        'insertAdjacentText': 'text_injection', 'textContent': 'text_injection',
    };

    function getSinkCategory(sink) {
        if (sink.startsWith('setAttribute')) return 'attr_injection';
        return _SINK_CATEGORIES[sink] || 'unknown';
    }
    function _safeSerialize(value) {
        try {
            if (typeof value === 'string') return value;
            return JSON.stringify(value);
        } catch(e) {
            try { return String(value); } catch(e2) { return ''; }
        }
    }
    function _describeTarget(t) {
        try {
            if (!t) return '';
            if (t.nodeType === 11 && t.host) return _describeTarget(t.host) + '::shadow';
            if (!t.tagName) return String(t.nodeName || '');
            return t.tagName.toLowerCase() + (t.id ? '#' + t.id : '');
        } catch (e) { return ''; }
    }
    function _recordSink(sink, value, target) {
        if (_sinkHits.length >= 500) return;
        const serialized = _safeSerialize(value);
        const canary = window.__canary;
        if (!canary || !serialized.includes(canary)) return;
        _sinkHits.push({
            sink, category: getSinkCategory(sink),
            snippet: serialized.slice(0, 300),
            target: _describeTarget(target),
            stack: (new Error()).stack || '',
            ts: Date.now(),
        });
    }

    try {
        const _origAttachShadow = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function(init) {
            const root = _origAttachShadow.call(this, init);
            // Record each attachShadow call: deduplicating by tag/id/class
            // undercounted repeated components and closed roots.
            _shadowLog.push({ tag: this.tagName, mode: init.mode });
            if (init && init.mode === 'closed') _closedRoots.push({ host: this, root });
            return root;
        };
        window.__shadowLog = _shadowLog;
    } catch(e) {}

    function hookProp(proto, prop) {
        try {
            const desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set) return;
            Object.defineProperty(proto, prop, {
                set(v) { _recordSink(prop, v, this); return desc.set.call(this, v); },
                get()  { return desc.get.call(this); },
                configurable: true,
            });
        } catch(e) {}
    }

    hookProp(Element.prototype, 'innerHTML');
    hookProp(Element.prototype, 'outerHTML');
    if (window.ShadowRoot)      hookProp(ShadowRoot.prototype, 'innerHTML');
    hookProp(DocumentFragment.prototype, 'textContent');
    if (window.HTMLTemplateElement) hookProp(HTMLTemplateElement.prototype, 'innerHTML');

    try {
        const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
        if (desc && desc.set) {
            Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
                set(v) { _recordSink('srcdoc', v, this); return desc.set.call(this, v); },
                get()  { return desc.get.call(this); },
                configurable: true,
            });
        }
    } catch(e) {}

    try {
        const _origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
            _recordSink('setAttribute', { attr: String(name).slice(0,40), value: String(value).slice(0,300) }, this);
            return _origSetAttr.call(this, name, value);
        };
    } catch(e) {}

    const _DOM_TARGETS  = [Element.prototype, DocumentFragment.prototype];
    const _HOOKED_METHODS = ['append','prepend','replaceChildren','replaceWith'];
    for (const target of _DOM_TARGETS) {
        for (const method of _HOOKED_METHODS) {
            try {
                const orig = target[method];
                if (!orig) continue;
                target[method] = function(...nodes) {
                    for (const n of nodes) {
                        try {
                            if (!n) continue;
                            if (n.nodeType === Node.TEXT_NODE) _recordSink(method, n.textContent, this);
                            else if (n.outerHTML) _recordSink(method, n.outerHTML, this);
                            else if (n.textContent) _recordSink(method, n.textContent, this);
                        } catch(e) {}
                    }
                    return orig.apply(this, nodes);
                };
            } catch(e) {}
        }
    }

    try {
        const _orig = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(pos, html) {
            _recordSink('insertAdjacentHTML', html, this); return _orig.call(this, pos, html);
        };
    } catch(e) {}

    try {
        const _orig = Element.prototype.insertAdjacentText;
        Element.prototype.insertAdjacentText = function(pos, text) {
            _recordSink('insertAdjacentText', text, this); return _orig.call(this, pos, text);
        };
    } catch(e) {}

    try {
        const _origWrite = document.write.bind(document);
        document.write = function(...args) { _recordSink('document.write', args.join('')); return _origWrite(...args); };
    } catch(e) {}

    try {
        const _origEval = window.eval;
        const wrappedEval = function wrappedEvalFn(code) { _recordSink('eval', code); return _origEval.call(this, code); };
        Object.defineProperty(wrappedEval, 'toString', { value: () => 'function eval() { [native code] }', configurable: true });
        Object.defineProperty(wrappedEval, 'name', { value: 'eval', configurable: true });
        window.eval = wrappedEval;
    } catch(e) {}

    try {
        const _origFn = window.Function;
        function Function(...args) {
            const body = args[args.length - 1] || '';
            _recordSink('Function', body);
            return new _origFn(...args);
        }
        Function.prototype = _origFn.prototype;
        Object.setPrototypeOf(Function, _origFn);
        Object.defineProperty(Function, 'toString',  { value: () => 'function Function() { [native code] }', configurable: true });
        Object.defineProperty(Function, 'length',    { value: 1, configurable: true });
        window.Function = Function;
    } catch(e) {}

    try {
        const _origSTO = window.setTimeout;
        window.setTimeout = function(fn, delay, ...rest) {
            if (typeof fn === 'string') _recordSink('setTimeout', fn);
            return _origSTO.call(window, fn, delay, ...rest);
        };
    } catch(e) {}

    try {
        const _origSI = window.setInterval;
        window.setInterval = function(fn, delay, ...rest) {
            if (typeof fn === 'string') _recordSink('setInterval', fn);
            return _origSI.call(window, fn, delay, ...rest);
        };
    } catch(e) {}

    try {
        const _orig = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function(html) { _recordSink('createContextualFragment', html); return _orig.call(this, html); };
    } catch(e) {}

    try {
        const _orig = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function(str, type) { _recordSink('DOMParser.parseFromString', str); return _orig.call(this, str, type); };
    } catch(e) {}

    try {
        if (Element.prototype.setHTMLUnsafe) {
            const _orig = Element.prototype.setHTMLUnsafe;
            Element.prototype.setHTMLUnsafe = function(html) { _recordSink('setHTMLUnsafe', html, this); return _orig.call(this, html); };
        }
    } catch(e) {}

    try {
        if (ShadowRoot.prototype.setHTML) {
            const _orig = ShadowRoot.prototype.setHTML;
            ShadowRoot.prototype.setHTML = function(html, opts) { _recordSink('ShadowRoot.setHTML', html, this); return _orig.call(this, html, opts); };
        }
    } catch(e) {}
})();
