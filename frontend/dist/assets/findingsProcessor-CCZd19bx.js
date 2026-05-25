(function() {
	self.onmessage = (u) => {
		try {
			const { type: n, findings: y, filters: r, sort: i } = u.data;
			if (n === "PROCESS_FINDINGS") {
				let t = [...y];
				if (r.severity && r.severity.length > 0 && (t = t.filter((e) => r.severity.includes(e.severity))), r.target && (t = t.filter((e) => e.target === r.target)), r.search) {
					const e = r.search.toLowerCase();
					t = t.filter((s) => s.title.toLowerCase().includes(e) || s.type.toLowerCase().includes(e) || s.description.toLowerCase().includes(e) || s.url?.toLowerCase().includes(e));
				}
				const a = /* @__PURE__ */ new Set();
				t = t.filter((e) => a.has(e.id) ? !1 : (a.add(e.id), !0));
				const l = {
					critical: 4,
					high: 3,
					medium: 2,
					low: 1,
					info: 0
				};
				t.sort((e, s) => {
					if (i.key === "severity") {
						const o = l[e.severity] ?? 0, c = l[s.severity] ?? 0;
						if (o !== c) return i.direction === "asc" ? o - c : c - o;
					}
					const f = e[i.key] ?? "", d = s[i.key] ?? "";
					return f < d ? i.direction === "asc" ? -1 : 1 : f > d ? i.direction === "asc" ? 1 : -1 : 0;
				}), self.postMessage({
					type: "PROCESS_COMPLETE",
					result: t
				});
			}
		} catch (n) {
			self.postMessage({
				type: "PROCESS_ERROR",
				error: n instanceof Error ? n.message : String(n)
			});
		}
	};
})();
