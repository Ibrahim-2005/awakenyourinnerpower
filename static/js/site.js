const menuButton = document.querySelector('.menu-toggle');
const nav = document.querySelector('#site-nav');
const navBackdrop = document.querySelector('.nav-backdrop');
if (menuButton && nav) {
  const setMenu = open => {
    menuButton.setAttribute('aria-expanded', String(open));
    menuButton.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    nav.classList.toggle('open', open);
    document.body.classList.toggle('menu-open', open);
  };
  menuButton.addEventListener('click', () => {
    setMenu(menuButton.getAttribute('aria-expanded') !== 'true');
  });
  navBackdrop?.addEventListener('click', () => setMenu(false));
  nav.querySelectorAll('a').forEach(link => link.addEventListener('click', () => setMenu(false)));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') setMenu(false);
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 900) setMenu(false);
  });
}

const siteHeader = document.querySelector('.site-header');
if (siteHeader) {
  const updateHeader = () => siteHeader.classList.toggle('scrolled', window.scrollY > 24);
  updateHeader();
  window.addEventListener('scroll', updateHeader, { passive: true });
}

document.querySelectorAll('.back-to-top').forEach(link => {
  link.addEventListener('click', event => {
    event.preventDefault();
    window.scrollTo({
      top: 0,
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'
    });
    if (history.replaceState) {
      history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }
  });
});

const dateInput = document.querySelector('#session_date');
const slotSelect = document.querySelector('#slot');
if (dateInput && slotSelect) {
  dateInput.addEventListener('change', async () => {
    slotSelect.disabled = true;
    slotSelect.innerHTML = '<option>Checking availability…</option>';
    try {
      const response = await fetch(`/api/availability?date=${encodeURIComponent(dateInput.value)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      slotSelect.innerHTML = data.available.length
        ? '<option value="">Choose a time</option>' + data.available.map(slot => `<option>${slot}</option>`).join('')
        : '<option value="">No times available</option>';
      slotSelect.disabled = !data.available.length;
    } catch (error) {
      slotSelect.innerHTML = '<option value="">Please try another date</option>';
    }
  });
}

const revealItems = document.querySelectorAll('.reveal');
revealItems.forEach((el, index) => {
  el.style.setProperty('--reveal-delay', `${Math.min(index % 5, 4) * 70}ms`);
});

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -4% 0px' });
revealItems.forEach(el => observer.observe(el));

document.querySelectorAll('details').forEach(item => {
  item.addEventListener('toggle', () => {
    if (item.open) document.querySelectorAll('details[open]').forEach(other => {
      if (other !== item) other.removeAttribute('open');
    });
  });
});

if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
  document.querySelectorAll('.service-card, .package-card, .about-card').forEach(card => {
    card.addEventListener('pointermove', event => {
      const rect = card.getBoundingClientRect();
      card.style.setProperty('--pointer-x', `${event.clientX - rect.left}px`);
      card.style.setProperty('--pointer-y', `${event.clientY - rect.top}px`);
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
    const menuBtn = document.querySelector('.admin-menu-toggle');
    const sidebar = document.querySelector('.admin-sidebar');

    if(menuBtn && sidebar){
        menuBtn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }
});