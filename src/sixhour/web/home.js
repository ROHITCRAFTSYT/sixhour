// Landing page: live six-hour clock, redaction demo, scroll reveals. No dependencies.
(() => {
  const SIX_HOURS = 6 * 3600 * 1000;
  const opened = Date.now();
  const clock = document.getElementById("hero-clock");
  const fmtTime = (d) => d.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" });
  const pad = (n) => String(n).padStart(2, "0");

  document.getElementById("hero-noticed").textContent = fmtTime(new Date(opened));
  document.getElementById("hero-due").textContent = fmtTime(new Date(opened + SIX_HOURS));

  const tick = () => {
    const left = Math.max(0, SIX_HOURS - (Date.now() - opened));
    const h = Math.floor(left / 3600000), m = Math.floor((left % 3600000) / 60000), s = Math.floor((left % 60000) / 1000);
    clock.textContent = pad(h) + ":" + pad(m) + ":" + pad(s);
  };
  tick();
  setInterval(tick, 1000);

  const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function redact(figure) {
    figure.querySelectorAll(".pii").forEach((span, i) => {
      setTimeout(() => {
        span.classList.add("barred");
        setTimeout(() => { span.textContent = span.dataset.token; span.classList.add("token"); }, calm ? 0 : 520);
      }, calm ? 0 : 500 + i * 450);
    });
  }

  if (!("IntersectionObserver" in window)) {
    document.querySelectorAll(".reveal").forEach((n) => n.classList.add("in"));
    redact(document.getElementById("redact-demo"));
    return;
  }
  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("in");
      if (entry.target.querySelector("#redact-demo")) redact(entry.target.querySelector("#redact-demo"));
      seen.unobserve(entry.target);
    }
  }, { threshold: 0.25 });
  document.querySelectorAll(".reveal, .thunk").forEach((n) => seen.observe(n));
})();
