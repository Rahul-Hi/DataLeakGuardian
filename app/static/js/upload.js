document.addEventListener("DOMContentLoaded", () => {
  const uploadForm = document.querySelector("form");
  const fileInput = document.getElementById("file");
  const dropzone = document.getElementById("dropzone");
  const previewCard = document.getElementById("file-preview");
  const previewName = document.getElementById("preview-name");
  const previewSize = document.getElementById("preview-size");
  const previewClear = document.getElementById("preview-clear");
  const clientAlert = document.getElementById("client-alert");
  const analyzeButton = document.getElementById("analyze-button");
  const analyzeSpinner = document.getElementById("analyze-spinner");
  const uploadProgress = document.getElementById("upload-progress");

  const MAX_BYTES = 5 * 1024 * 1024;
  const ALLOWED_EXTS = [".pdf", ".png", ".jpg", ".jpeg"];

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  function showAlert(msg) {
    if (!clientAlert) return;
    clientAlert.textContent = msg;
    clientAlert.classList.remove("d-none");
  }

  function hideAlert() {
    if (!clientAlert) return;
    clientAlert.textContent = "";
    clientAlert.classList.add("d-none");
  }

  function handleFileSelected(file) {
    hideAlert();
    if (!file) {
      if (previewCard) previewCard.classList.add("d-none");
      return;
    }

    const ext = "." + file.name.split(".").pop().toLowerCase();
    if (!ALLOWED_EXTS.includes(ext)) {
      showAlert("Unsupported file type. Please upload a PDF, PNG, JPG, or JPEG file.");
      fileInput.value = "";
      if (previewCard) previewCard.classList.add("d-none");
      return;
    }

    if (file.size > MAX_BYTES) {
      showAlert("File size exceeds the 5 MB limit. Please select a smaller document.");
      fileInput.value = "";
      if (previewCard) previewCard.classList.add("d-none");
      return;
    }

    if (previewCard && previewName && previewSize) {
      previewName.textContent = file.name;
      previewSize.textContent = formatBytes(file.size);
      previewCard.classList.remove("d-none");
    }
  }

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files.length > 0) {
        handleFileSelected(fileInput.files[0]);
      }
    });
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener("click", (e) => {
      if (e.target !== previewClear && !previewClear?.contains(e.target)) {
        fileInput.click();
      }
    });

    ["dragenter", "dragover"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      });
    });

    ["dragleave", "dragend", "drop"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      });
    });

    dropzone.addEventListener("drop", (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        handleFileSelected(fileInput.files[0]);
      }
    });
  }

  if (previewClear && fileInput) {
    previewClear.addEventListener("click", (e) => {
      e.stopPropagation();
      fileInput.value = "";
      if (previewCard) previewCard.classList.add("d-none");
      hideAlert();
    });
  }

  if (uploadForm) {
    uploadForm.addEventListener("submit", (event) => {
      if (!uploadForm.reportValidity()) {
        event.preventDefault();
        return;
      }
      if (fileInput.files && fileInput.files.length > 0) {
        const file = fileInput.files[0];
        if (file.size <= 0) {
          event.preventDefault();
          showAlert("Selected file is empty (0 bytes). Please choose a valid document.");
          return;
        }
        if (file.size > MAX_BYTES) {
          event.preventDefault();
          showAlert("File size exceeds the 5 MB limit.");
          return;
        }
      }
      if (analyzeButton) analyzeButton.disabled = true;
      if (analyzeSpinner) analyzeSpinner.classList.remove("d-none");
      if (uploadProgress) {
        uploadProgress.classList.remove("d-none");
        const steps = uploadProgress.querySelectorAll(".stepper-step");
        if (steps && steps.length >= 3) {
          setTimeout(() => {
            steps[0].classList.add("text-success");
            const ind0 = steps[0].querySelector(".stepper-indicator");
            if (ind0) ind0.textContent = "✓";
            steps[1].classList.add("active");
          }, 800);
          setTimeout(() => {
            steps[1].classList.add("text-success");
            const ind1 = steps[1].querySelector(".stepper-indicator");
            if (ind1) ind1.textContent = "✓";
            steps[2].classList.add("active");
          }, 1800);
        }
      }
    });
  }
});
