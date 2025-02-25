document.addEventListener("DOMContentLoaded", () => {
    const toggleThemeBtn = document.getElementById("toggle-theme");
    const body = document.body;
  
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) {
      body.classList.add(savedTheme);
    } else {
      body.classList.add("light"); // Tema por defecto
    }
  
    toggleThemeBtn.addEventListener("click", () => {
      if (body.classList.contains("light")) {
        body.classList.replace("light", "dark");
        localStorage.setItem("theme", "dark");
      } else {
        body.classList.replace("dark", "light");
        localStorage.setItem("theme", "light");
      }
    });
  });
  