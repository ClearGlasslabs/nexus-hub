const protectedAreas = document.querySelectorAll('.protected');
protectedAreas.forEach((element) => {
  element.addEventListener('contextmenu', (event) => event.preventDefault());
  element.querySelectorAll('img, .drag-block').forEach((item) => {
    item.draggable = false;
    item.addEventListener('dragstart', (event) => event.preventDefault());
  });
});

document.addEventListener('keydown', (event) => {
  const shortcut = (event.ctrlKey || event.metaKey) && ['c', 'u', 's', 'p'].includes(event.key.toLowerCase());
  const protectedFocus = document.activeElement?.closest?.('.protected');
  if (shortcut && (protectedFocus || document.querySelector('.protected:hover'))) event.preventDefault();
});

const token = crypto.getRandomValues(new Uint32Array(2)).join('').slice(0, 10);
document.documentElement.dataset.sessionWatermark = token;
const watermarkMeta = document.createElement('meta');
watermarkMeta.name = 'session-watermark';
watermarkMeta.content = token;
document.head.appendChild(watermarkMeta);

const progress = document.querySelector('#reading-progress');
function updateProgress() {
  const distance = document.documentElement.scrollHeight - innerHeight;
  progress.style.width = `${distance > 0 ? (scrollY / distance) * 100 : 0}%`;
}
addEventListener('scroll', updateProgress, { passive: true });

const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => entry.target.classList.toggle('visible', entry.isIntersecting));
}, { threshold: 0.08 });
document.querySelectorAll('.reveal').forEach((element) => observer.observe(element));

const dialog = document.querySelector('#brief-dialog');
document.querySelector('#brief-button').addEventListener('click', () => dialog.showModal());
document.querySelector('#dialog-close').addEventListener('click', () => dialog.close());
dialog.addEventListener('click', (event) => {
  if (event.target === dialog) dialog.close();
});

const canvas = document.querySelector('#network-canvas');
const context = canvas.getContext('2d');
const nodes = Array.from({ length: 28 }, (_, index) => ({
  angle: (index / 28) * Math.PI * 2,
  radius: 105 + ((index * 47) % 190),
  size: index % 7 === 0 ? 3 : 1.6,
  speed: .00004 + (index % 5) * .000006,
}));
function drawNetwork(time = 0, animate = true) {
  const scale = devicePixelRatio || 1;
  const bounds = canvas.getBoundingClientRect();
  if (canvas.width !== bounds.width * scale || canvas.height !== bounds.height * scale) {
    canvas.width = bounds.width * scale; canvas.height = bounds.height * scale;
  }
  context.setTransform(scale, 0, 0, scale, 0, 0);
  context.clearRect(0, 0, bounds.width, bounds.height);
  const center = { x: bounds.width / 2, y: bounds.height / 2 };
  const points = nodes.map((node) => ({ x: center.x + Math.cos(node.angle + time * node.speed) * node.radius, y: center.y + Math.sin(node.angle + time * node.speed) * node.radius * .72, ...node }));
  context.strokeStyle = 'rgba(165,244,50,.14)'; context.lineWidth = .7;
  points.forEach((point, index) => {
    context.beginPath(); context.moveTo(center.x, center.y); context.lineTo(point.x, point.y); context.stroke();
    if (index % 4 === 0) { const next = points[(index + 5) % points.length]; context.beginPath(); context.moveTo(point.x, point.y); context.lineTo(next.x, next.y); context.stroke(); }
  });
  points.forEach((point) => { context.fillStyle = point.size > 2 ? '#a5f432' : 'rgba(216,255,145,.65)'; context.beginPath(); context.arc(point.x, point.y, point.size, 0, Math.PI * 2); context.fill(); });
  if (animate) requestAnimationFrame(drawNetwork);
}
if (!matchMedia('(prefers-reduced-motion: reduce)').matches) requestAnimationFrame(drawNetwork); else drawNetwork(0, false);
