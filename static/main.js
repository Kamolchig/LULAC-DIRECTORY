document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('.card, form, table').forEach(el => {
    el.style.opacity = 0;
    el.style.transform = "translateY(30px)";
    setTimeout(() => {
      el.style.transition = "opacity 0.8s, transform 0.8s";
      el.style.opacity = 1;
      el.style.transform = "translateY(0)";
    }, 200);
  });

  document.getElementById('toggle-theme').onclick = function() {
    document.body.classList.toggle('dark-mode');
  };

  document.querySelectorAll('.btn-primary').forEach(btn => {
    btn.addEventListener('click', function(e) {
      btn.classList.add('clicked');
      setTimeout(() => btn.classList.remove('clicked'), 300);
    });
  });
});

window.onload = function() {
  document.getElementById('loader').style.display = 'none';
};