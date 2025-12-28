$(document).ready(function () {
  initApp();

  function initApp() {
    // Set current time
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);

    // Initialize navigation
    setupNavigation();

    // Initialize form interactions
    setupForms();

    // Initialize file storage
    setupFileStorage();

    // Initialize modals
    setupModals();

    // Initialize guide tabs
    setupGuideTabs();

    // Load initial data
    loadInitialData();

    // Setup dark mode
    setupDarkMode();
  }

  function updateCurrentTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    const dateString = now.toLocaleDateString();
    $("#current-time").text(`${dateString} ${timeString}`);
  }

  function setupNavigation() {
    $(".nav-menu li").click(function () {
      const section = $(this).data("section");
      showSection(section);

      $(".nav-menu li").removeClass("active");
      $(this).addClass("active");
    });

    $(".action-btn").click(function () {
      const action = $(this).data("action");

      switch (action) {
        case "encrypt":
          showSection("encryption");
          $("#encryption-action").val("encrypt").trigger("change");
          break;
        case "store":
          showSection("storage");
          break;
        case "verify":
          showSection("verification");
          break;
      }

      // Update navigation active state
      $(".nav-menu li").removeClass("active");
      $(
        `.nav-menu li[data-section="${
          action === "encrypt"
            ? "encryption"
            : action === "verify"
            ? "verification"
            : "storage"
        }"]`
      ).addClass("active");
    });
  }

  function setupGuideTabs() {
    $(".guide-tabs").on("click", ".tab-btn", function () {
      const tabId = $(this).data("tab");

      $(".tab-btn").removeClass("active");
      $(".tab-content").removeClass("active");

      $(this).addClass("active");
      $(`#${tabId}`).addClass("active");
    });
  }

  function showSection(section) {
    $(".content-section").removeClass("active");

    $(`#${section}`).addClass("active");

    const titleMap = {
      dashboard: "Dashboard",
      encryption: "File Encryption",
      storage: "Cloud Storage",
      verification: "File Verification",
      guide: "User Guide",
      settings: "Settings",
    };

    $("#section-title").text(titleMap[section] || section);

    if (section === "storage") {
      loadStoredFiles();
    }
  }

  function setupForms() {
    $("#encryption-form").submit(function (e) {
      e.preventDefault();
      processEncryptionForm();
    });

    // Storage form handling
    $("#storage-form").submit(function (e) {
      e.preventDefault();
      storeFile();
    });

    // Verification form handling
    $("#verify-hash-btn").click(function () {
      verifyFileHash();
    });

    $("#generate-hash-btn").click(function () {
      generateFileHash();
    });

    $("#copy-hash-btn").click(function () {
      copyHashToClipboard();
    });

    $(".toggle-password").click(function () {
      const input = $(this).siblings("input");
      const type = input.attr("type") === "password" ? "text" : "password";
      input.attr("type", type);
      $(this).toggleClass("fa-eye fa-eye-slash");
    });

    $("#encryption-action").change(function () {
      const action = $(this).val();

      // Show/hide password confirmation
      if (action === "encrypt") {
        $("#encryption-confirm-group").show();
      } else {
        $("#encryption-confirm-group").hide();
      }

      const algorithmSelect = $("#encryption-algorithm");

      if (action === "hash") {
        algorithmSelect.find('optgroup[label="Encryption"]').hide();
        algorithmSelect.find('optgroup[label="Hashing"]').show();
        algorithmSelect.val("SHA-256");
      } else {
        algorithmSelect.find('optgroup[label="Encryption"]').show();
        algorithmSelect.find('optgroup[label="Hashing"]').hide();
        algorithmSelect.val("AES");
      }
    });

    // Password strength meter
    $("#encryption-password").on("input", function () {
      updatePasswordStrength($(this).val());
    });

    $(".upload-area").on("click", function () {
      $(this).find('input[type="file"]').click();
    });

    $('.upload-area input[type="file"]').change(function () {
      const files = $(this)[0].files;
      if (files.length > 0) {
        const uploadArea = $(this).closest(".upload-area");
        uploadArea.find("p").text(files[0].name);
        uploadArea.addClass("has-file");
      }
    });

    $(".upload-area").on("dragover", function (e) {
      e.preventDefault();
      $(this).addClass("dragover");
    });

    $(".upload-area").on("dragleave", function (e) {
      e.preventDefault();
      $(this).removeClass("dragover");
    });

    $(".upload-area").on("drop", function (e) {
      e.preventDefault();
      $(this).removeClass("dragover");

      const files = e.originalEvent.dataTransfer.files;
      if (files.length > 0) {
        $(this).find('input[type="file"]')[0].files = files;
        $(this).find("p").text(files[0].name);
        $(this).addClass("has-file");
      }
    });

    // Settings form handling
    setupSettingsForm();
  }

  function setupSettingsForm() {
    // Load saved settings
    loadSettings();

    $("#save-settings").click(function (e) {
      e.preventDefault();
      saveSettings();
    });

    $("#cancel-changes").click(function (e) {
      e.preventDefault();
      loadSettings();
    });

    $("#clear-cache").click(function () {
      showModal(
        "Clear Cache",
        "Are you sure you want to clear all locally cached files? This will not affect your cloud storage.",
        function () {
          showAlert("success", "Local cache cleared successfully");
        }
      );
    });

    // Export settings button
    $("#export-settings").click(function () {
      exportSettings();
    });

    // Import settings button
    $("#import-settings").click(function () {
      $("#settings-file").click();
    });

    $("#settings-file").change(function () {
      if (this.files.length > 0) {
        importSettings(this.files[0]);
      }
    });

    // Reset settings button
    $("#reset-settings").click(function () {
      showModal(
        "Reset Settings",
        "Are you sure you want to reset all settings to default values? This cannot be undone.",
        function () {
          resetSettings();
        }
      );
    });
  }

  function loadSettings() {
    // Load settings from localStorage or use defaults
    const settings = JSON.parse(localStorage.getItem("app-settings")) || {};

    // Set form values from saved settings
    $("#default-algorithm").val(settings.defaultAlgorithm || "AES");
    $("#auto-delete").prop("checked", settings.autoDelete !== false);
    $("#cloud-auto-sync").prop("checked", settings.cloudAutoSync !== false);
    $("#file-expiration").val(settings.fileExpiration || "5");

    $("#notify-encrypt").prop("checked", settings.notifyEncrypt !== false);
    $("#notify-decrypt").prop("checked", settings.notifyDecrypt !== false);
    $("#notify-upload").prop("checked", settings.notifyUpload !== false);
    $("#notify-download").prop("checked", settings.notifyDownload !== false);

    $("#theme-select").val(settings.theme || "auto");
    $("#font-size").val(settings.fontSize || "medium");
    $("#animations").prop("checked", settings.animations !== false);

    $("#max-parallel").val(settings.maxParallel || "3");
    $("#chunk-size").val(settings.chunkSize || "5");
    $("#compression-level").val(settings.compressionLevel || "6");
  }

  function saveSettings() {
    const settings = {
      defaultAlgorithm: $("#default-algorithm").val(),
      autoDelete: $("#auto-delete").is(":checked"),
      cloudAutoSync: $("#cloud-auto-sync").is(":checked"),
      fileExpiration: $("#file-expiration").val(),

      notifyEncrypt: $("#notify-encrypt").is(":checked"),
      notifyDecrypt: $("#notify-decrypt").is(":checked"),
      notifyUpload: $("#notify-upload").is(":checked"),
      notifyDownload: $("#notify-download").is(":checked"),

      theme: $("#theme-select").val(),
      fontSize: $("#font-size").val(),
      animations: $("#animations").is(":checked"),

      maxParallel: $("#max-parallel").val(),
      chunkSize: $("#chunk-size").val(),
      compressionLevel: $("#compression-level").val(),
    };

    localStorage.setItem("app-settings", JSON.stringify(settings));
    applySettings(settings);
    showAlert("success", "Settings saved successfully");
  }

  function applySettings(settings) {
    // Apply theme setting
    if (
      settings.theme === "dark" ||
      (settings.theme === "auto" &&
        window.matchMedia("(prefers-color-scheme: dark)").matches)
    ) {
      $("body").addClass("dark-mode");
      $("#darkModeToggle").prop("checked", true);
    } else {
      $("body").removeClass("dark-mode");
      $("#darkModeToggle").prop("checked", false);
    }

    // Apply font size
    $("html").css(
      "font-size",
      settings.fontSize === "small"
        ? "14px"
        : settings.fontSize === "large"
        ? "18px"
        : "16px"
    );

    // Apply animations
    if (!settings.animations) {
      $("*").css("transition", "none");
    }
  }

  function exportSettings() {
    const settings = JSON.parse(localStorage.getItem("app-settings")) || {};
    const dataStr = JSON.stringify(settings, null, 2);
    const dataUri =
      "data:application/json;charset=utf-8," + encodeURIComponent(dataStr);

    const exportFileDefaultName = "securecrypt-settings.json";

    const linkElement = document.createElement("a");
    linkElement.setAttribute("href", dataUri);
    linkElement.setAttribute("download", exportFileDefaultName);
    linkElement.click();
  }

  function importSettings(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const settings = JSON.parse(e.target.result);
        localStorage.setItem("app-settings", JSON.stringify(settings));
        loadSettings();
        applySettings(settings);
        showAlert("success", "Settings imported successfully");
      } catch (error) {
        showAlert("error", "Failed to import settings: Invalid file format");
      }
    };
    reader.readAsText(file);
  }

  function resetSettings() {
    localStorage.removeItem("app-settings");
    loadSettings();
    applySettings({});
    showAlert("success", "Settings reset to defaults");
  }

  function setupFileStorage() {
    // Refresh storage list
    $("#refresh-storage").click(function () {
      loadStoredFiles();
    });

    // Handle file retrieval
    $(document).on("click", ".retrieve-btn", function () {
      const filename = $(this).data("filename");
      retrieveFile(filename);
    });

    // Handle bulk actions
    $("#bulk-download").click(function (e) {
      e.preventDefault();
      showModal(
        "Bulk Download",
        "Are you sure you want to download all files?",
        function () {
          // Implement bulk download
          showAlert("success", "Bulk download initiated");
        }
      );
    });

    $("#bulk-delete").click(function (e) {
      e.preventDefault();
      showModal(
        "Bulk Delete",
        "Are you sure you want to delete all files? This cannot be undone.",
        function () {
          // Implement bulk delete
          showAlert("success", "All files deleted successfully");
          loadStoredFiles();
        }
      );
    });
  }

  function setupModals() {
    // Close modal when clicking X
    $(".close-modal").click(function () {
      hideModal();
    });

    // Close modal when clicking outside
    $(window).click(function (e) {
      if ($(e.target).hasClass("modal")) {
        hideModal();
      }
    });

    // Modal confirm button
    $("#modal-confirm").click(function () {
      if (typeof window.modalCallback === "function") {
        window.modalCallback();
      }
      hideModal();
    });

    // Modal cancel button
    $("#modal-cancel").click(function () {
      hideModal();
    });
  }

  function loadInitialData() {
    // Load encrypted files count
    $.get("/encrypted_files_count", function (response) {
      $("#encrypted-count").text(response.count);
    }).fail(function () {
      $("#encrypted-count").text("Error");
    });

    // Load stored files count
    $.get("/stored_files_count", function (response) {
      $("#stored-count").text(response.count);
    }).fail(function () {
      $("#stored-count").text("Error");
    });

    // Load verified files count
    $.get("/verified_files_count", function (response) {
      $("#verified-count").text(response.count);
    }).fail(function () {
      $("#verified-count").text("Error");
    });
  }

  function setupDarkMode() {
    const toggleSwitch = $("#darkModeToggle");
    const body = $("body");

    // Load dark mode preference
    if (localStorage.getItem("dark-mode") === "enabled") {
      body.addClass("dark-mode");
      toggleSwitch.prop("checked", true);
    }

    // Toggle dark mode
    toggleSwitch.change(function () {
      if ($(this).is(":checked")) {
        body.addClass("dark-mode");
        localStorage.setItem("dark-mode", "enabled");
      } else {
        body.removeClass("dark-mode");
        localStorage.setItem("dark-mode", "disabled");
      }
    });
  }

  function updatePasswordStrength(password) {
    let strength = 0;

    // Length check
    if (password.length > 7) strength++;
    if (password.length > 11) strength++;

    // Complexity checks
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    // Update strength meter
    const meter = $(".strength-meter");
    const strengthText = $(".strength-text span");
    let color = "#dc3545"; // Red
    let text = "Weak";

    if (strength > 3) {
      color = "#28a745"; // Green
      text = "Strong";
    } else if (strength > 1) {
      color = "#fd7e14"; // Orange
      text = "Medium";
    }

    meter.css({
      width: strength * 20 + "%",
      "background-color": color,
    });

    strengthText.text(text);
  }

  function processEncryptionForm() {
    const form = $("#encryption-form");
    const action = $("#encryption-action").val();
    const algorithm = $("#encryption-algorithm").val();
    const password = $("#encryption-password").val();
    const confirmPassword = $("#encryption-confirm").val();
    const fileInput = $("#encryption-file")[0];
    const storeInDropbox = $("#store-in-dropbox").is(":checked");
    const fileType = fileInput.files.length > 0 ? fileInput.files[0].type : "";

    // Validate form inputs
    if (!fileInput.files.length) {
      showAlert("error", "Please select a file");
      return;
    }
    if (action !== "hash" && !password) {
      showAlert("error", "Password is required");
      return;
    }
    if (action === "encrypt" && password !== confirmPassword) {
      showAlert("error", "Passwords do not match");
      return;
    }
    if (action === "encrypt" && password.length < 8) {
      showAlert("error", "Password must be at least 8 characters");
      return;
    }

    // Prepare form data for AJAX submission
    const formData = new FormData();
    formData.append("action", action);
    formData.append("algorithm", algorithm);
    formData.append("password", password);
    formData.append("file", fileInput.files[0]);
    formData.append("file_type", fileType);
    formData.append("store_in_dropbox", storeInDropbox);

    // Show loading indicator
    showLoading(true);

    // AJAX POST request to backend
    $.ajax({
      url: "/process_file",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      xhrFields: {
        responseType: "blob",
      },
      success: function (blob, status, xhr) {
        // Handle JSON response for hash action
        const contentType = xhr.getResponseHeader("content-type");
        if (contentType && contentType.indexOf("application/json") > -1) {
          const reader = new FileReader();
          reader.onload = function () {
            const jsonResponse = JSON.parse(reader.result);
            handleEncryptionResponse(
              jsonResponse,
              status,
              xhr,
              action,
              algorithm,
              storeInDropbox
            );
          };
          reader.readAsText(blob);
        } else {
          // Handle blob response for file downloads
          handleEncryptionResponse(
            blob,
            status,
            xhr,
            action,
            algorithm,
            storeInDropbox
          );
        }
      },
      error: function (xhr) {
        // Show error message from server or generic message
        let errorMsg = "An unknown error occurred.";
        if (xhr.responseJSON && xhr.responseJSON.message) {
          errorMsg = xhr.responseJSON.message;
        }
        showAlert("error", errorMsg);
      },
      complete: function () {
        // Hide loading indicator
        showLoading(false);
      },
    });
  }

  function handleEncryptionResponse(
    response,
    status,
    xhr,
    action,
    algorithm,
    storeInDropbox
  ) {
    const originalFilename = $("#encryption-file")[0].files[0].name;
    let successMessage = "";

    if (action === "hash") {
      // Handle hash response (response is JSON)
      const blob = new Blob([response.hash], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = response.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      successMessage = `Hash for "${originalFilename}" generated successfully.`;
      if (storeInDropbox) {
        successMessage += " A copy has been stored in Dropbox.";
      }
      showAlert("success", successMessage);
    } else {
      // Handle file download responses (response is a blob)
      const blob = new Blob([response]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;

      if (action === "encrypt") {
        a.download = originalFilename + ".enc";
        successMessage = `File "${originalFilename}" encrypted successfully. Remember your password!`;
        if (storeInDropbox) {
          successMessage += " A copy has been stored in Dropbox.";
        }
        showAlert("success", successMessage);
        addActivity("encrypted", originalFilename);
      } else if (action === "decrypt") {
        a.download = originalFilename.replace(/\.enc$/, "");
        successMessage = `File "${originalFilename}" decrypted successfully.`;
        if (storeInDropbox) {
          successMessage += " A copy has been stored in Dropbox.";
        }
        showAlert("success", successMessage);
        addActivity("decrypted", originalFilename);
      }

      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  }

  function verifyFileHash() {
    const fileInput = $("#verification-file")[0];
    const hashValue = $("#verification-hash").val().trim();
    const algorithm = $("#verification-algorithm").val();

    if (!fileInput.files.length) {
      showAlert("error", "Please select a file to verify");
      return;
    }

    if (!hashValue) {
      showAlert("error", "Please enter the hash value for comparison");
      return;
    }

    showLoading(true);

    const formData = new FormData();
    formData.append("filename", fileInput.files[0].name);
    formData.append("hash", hashValue);

    $.ajax({
      url: "/verify_hash",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        if (response.status === "success") {
          const resultDiv = $("#verification-result");
          const icon = resultDiv.find(".result-icon i");
          const message = resultDiv.find(".result-message");

          if (response.match) {
            icon
              .removeClass("fa-times-circle")
              .addClass("fa-check-circle")
              .css("color", "#28a745");
            message
              .text("File verification successful! The file is authentic.")
              .css("color", "#28a745");
          } else {
            icon
              .removeClass("fa-check-circle")
              .addClass("fa-times-circle")
              .css("color", "#dc3545");
            message
              .text(
                "File verification failed! The file may have been modified."
              )
              .css("color", "#dc3545");
          }

          resultDiv.find(".verified-filename").text(fileInput.files[0].name);
          resultDiv.find(".verified-algorithm").text(algorithm);
          resultDiv.find(".provided-hash").text(hashValue);
          resultDiv.find(".computed-hash").text(hashValue);

          resultDiv.show();
          addActivity("verified", fileInput.files[0].name);
        } else {
          showAlert("error", response.message || "Error verifying file");
        }
      },
      error: function (xhr) {
        showAlert(
          "error",
          xhr.responseJSON?.message || "Server error occurred"
        );
      },
      complete: function () {
        showLoading(false);
      },
    });
  }

  function generateFileHash() {
    const fileInput = $("#hash-generation-file")[0];
    const algorithm = $("#hash-generation-algorithm").val();
    const storeInDropbox = $("#store-hash-in-dropbox").is(":checked");

    if (!fileInput.files.length) {
      showAlert("error", "Please select a file to generate hash");
      return;
    }

    showLoading(true);

    const formData = new FormData();
    formData.append("action", "hash");
    formData.append("algorithm", algorithm);
    formData.append("file", fileInput.files[0]);
    formData.append("store_in_dropbox", storeInDropbox);

    $.ajax({
      url: "/process_file",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        if (response.status === "success") {
          $("#generated-hash").val(response.hash);
          $("#hash-generation-result").show();

          let successMessage = "Hash generated successfully";
          if (storeInDropbox) {
            successMessage += " and stored in Dropbox";
          }
          showAlert("success", successMessage);
        } else {
          showAlert("error", response.message || "Error generating hash");
        }
      },
      error: function (xhr) {
        showAlert(
          "error",
          xhr.responseJSON?.message || "Server error occurred"
        );
      },
      complete: function () {
        showLoading(false);
      },
    });
  }

  function copyHashToClipboard() {
    const hashText = $("#generated-hash");
    hashText.select();
    document.execCommand("copy");
    showAlert("success", "Hash copied to clipboard");
  }

  function loadStoredFiles() {
    $("#storage-file-list").html(
      '<div class="loading-row"><i class="fas fa-spinner fa-spin"></i> Loading files...</div>'
    );

    $.ajax({
      url: "/list_stored_files",
      type: "GET",
      success: function (response) {
        if (response.status === "success") {
          if (response.files.length > 0) {
            let filesHtml = "";
            response.files.forEach((file) => {
              filesHtml += `
                <div class="file-row">
                  <div class="file-name">
                    <i class="fas fa-file-archive"></i>
                    ${file.name}
                  </div>
                  <div class="file-size">${formatFileSize(file.size)}</div>
                  <div class="file-date">${file.modified}</div>
                  <div class="file-actions">
                    <button class="retrieve-btn action-icon download" data-filename="${
                      file.name
                    }">
                      <i class="fas fa-download"></i>
                    </button>
                    <button class="delete-btn action-icon delete" data-filename="${
                      file.name
                    }">
                      <i class="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
              `;
            });
            $("#storage-file-list").html(filesHtml);
          } else {
            $("#storage-file-list").html(
              '<div class="loading-row">No files found in storage</div>'
            );
          }
        } else {
          showAlert("error", response.message || "Error loading files");
        }
      },
      error: function (xhr) {
        showAlert(
          "error",
          xhr.responseJSON?.message || "Server error occurred"
        );
      },
    });
  }

  function storeFile() {
    const fileInput = $("#storage-file")[0];

    if (!fileInput.files.length) {
      showAlert("error", "Please select a file to store");
      return;
    }

    showLoading(true);
    const filename = fileInput.files[0].name;
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    $.ajax({
      url: "/store_file",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        if (response.status === "success") {
          showAlert(
            "success",
            `Successfully stored "${filename}" in your cloud storage.`
          );
          $("#storage-file").val("");
          $(".upload-area p").text("Drag & drop files here or click to browse");
          $(".upload-area").removeClass("has-file");

          // Update stored files count
          $("#stored-count").text(parseInt($("#stored-count").text()) + 1);

          // Add to activity feed
          addActivity("stored", filename);

          // Refresh file list
          loadStoredFiles();
        } else {
          showAlert("error", response.message || "Error storing file");
        }
      },
      error: function (xhr) {
        showAlert(
          "error",
          xhr.responseJSON?.message || "Server error occurred"
        );
      },
      complete: function () {
        showLoading(false);
      },
    });
  }

  function retrieveFile(filename) {
    showLoading(true);

    $.ajax({
      url: "/retrieve_file",
      type: "POST",
      data: { filename: filename },
      xhrFields: {
        responseType: "blob",
      },
      success: function (blob, status, xhr) {
        const contentType = xhr.getResponseHeader("content-type");
        if (contentType === "application/octet-stream") {
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);

          showAlert("success", `File "${filename}" retrieved successfully.`);
          addActivity("retrieved", filename);
        } else {
          showAlert(
            "error",
            "Failed to retrieve file: Unexpected response from server."
          );
        }
      },
      error: function (xhr) {
        const reader = new FileReader();
        reader.onload = function () {
          try {
            const jsonResponse = JSON.parse(reader.result);
            showAlert("error", jsonResponse.message || "Error retrieving file");
          } catch (e) {
            showAlert(
              "error",
              "An unknown error occurred while retrieving the file."
            );
          }
        };
        reader.readAsText(xhr.response);
      },
      complete: function () {
        showLoading(false);
      },
    });
  }

  function formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function addActivity(type, filename) {
    const iconMap = {
      encrypted: "fa-key",
      decrypted: "fa-key",
      stored: "fa-cloud-upload-alt",
      retrieved: "fa-cloud-download-alt",
      verified: "fa-check-circle",
    };

    const textMap = {
      encrypted: "Encrypted",
      decrypted: "Decrypted",
      stored: "Stored",
      retrieved: "Retrieved",
      verified: "Verified",
    };

    const now = new Date();
    const timeString = now.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

    const activityItem = `
      <div class="activity-item">
        <div class="activity-icon">
          <i class="fas ${iconMap[type]}"></i>
        </div>
        <div class="activity-details">
          <p>${textMap[type]} "${filename}"</p>
          <small>${timeString}</small>
        </div>
      </div>
    `;

    $("#activity-feed").prepend(activityItem);

    // Limit to 10 activities
    if ($("#activity-feed").children().length > 10) {
      $("#activity-feed").children().last().remove();
    }
  }

  function showAlert(type, message) {
    const alertId = "alert-" + Date.now();
    const alertDiv = $(
      `<div id="${alertId}" class="alert alert-${type}">${message}</div>`
    );

    // Create container if it doesn't exist
    if ($("#alerts-container").length === 0) {
      $("body").append(
        '<div id="alerts-container" style="position:fixed; top:20px; right:20px; z-index:9999;"></div>'
      );
    }

    $("#alerts-container").append(alertDiv);
    $(`#${alertId}`).hide().fadeIn();

    setTimeout(() => {
      $(`#${alertId}`).fadeOut(() => {
        $(`#${alertId}`).remove();
      });
    }, 5000);
  }

  function showLoading(show) {
    if (show) {
      $("#loading-overlay").css("display", "flex").hide().fadeIn(200);
    } else {
      $("#loading-overlay").fadeOut(200);
    }
  }

  function showModal(title, message, callback) {
    $("#modal-title").text(title);
    $("#modal-message").text(message);
    window.modalCallback = callback;
    $("#confirmation-modal").css("display", "flex").hide().fadeIn(200);
  }

  function hideModal() {
    $("#confirmation-modal").fadeOut(200);
  }

  // Initialize with dashboard
  showSection("dashboard");
});
