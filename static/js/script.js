// static/js/script.js
// TelePorte Frontend
// - Abas funcionais
// - Animações
// - Geração de Pix com TXID
// - Hash mestre para teste
// - Mercado Pago (comentado)
// - Desenvolvido por Genis R Lopes

document.addEventListener('DOMContentLoaded', function () {
  // === Abas (Contratar / Prestar) ===
  const tabs = document.querySelectorAll('.main-tab');
  const contents = document.querySelectorAll('.tab-content');

  function activateTab(tabId) {
    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));

    document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      e.preventDefault();
      activateTab(tab.dataset.tab);
    });
  });

  // Ativa a primeira aba por padrão
  if (tabs[0]) activateTab(tabs[0].dataset.tab);

  // === Navegação Suave ===
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        window.scrollTo({
          top: target.offsetTop - 80,
          behavior: 'smooth'
        });
      }
    });
  });

  // === Animação ao rolar ===
  const fadeIns = document.querySelectorAll('.fade-in');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = 1;
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, { threshold: 0.1 });

  fadeIns.forEach(el => {
    el.style.opacity = 0;
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'all 0.6s ease-out';
    observer.observe(el);
  });

  // === Gamificação: Nível e Pontos (exemplo) ===
  const nivel = Math.floor(Math.random() * 10) + 1;
  const pontos = Math.floor(Math.random() * 500);

  const nivelEl = document.querySelector('.nivel');
  const pontosEl = document.querySelector('.pontos');

  if (nivelEl) nivelEl.textContent = `Nível ${nivel}`;
  if (pontosEl) pontosEl.textContent = `${pontos} pts`;
});