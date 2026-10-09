document.addEventListener("DOMContentLoaded", () => {
  const deleteForms = document.querySelectorAll("form.delete-scan-form");
  deleteForms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      const confirmMessage = form.getAttribute("data-confirm") || "Delete this scan and its files?";
      if (!window.confirm(confirmMessage)) {
        event.preventDefault();
      }
    });
  });
});
