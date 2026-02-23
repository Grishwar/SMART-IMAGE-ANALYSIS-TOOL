const form = document.getElementById("uploadForm");
const output = document.getElementById("output");
const loading = document.getElementById("loading");
const downloadBtn = document.getElementById("downloadBtn");

form.addEventListener("submit", async function(e) {
    e.preventDefault();

    const files = document.getElementById("files").files;
    if(files.length === 0) return;

    const formData = new FormData();
    for (let file of files) {
        formData.append("files", file);
    }

    output.value = "";
    loading.classList.remove("hidden");
    downloadBtn.classList.add("hidden");

    try {
        const res = await fetch("/analyze", {
            method: "POST",
            body: formData
        });

        const text = await res.text();

        loading.classList.add("hidden");
        output.value = text;
        downloadBtn.classList.remove("hidden");

    } catch(err) {
        loading.classList.add("hidden");
        output.value = "Server error: " + err;
    }
});


downloadBtn.addEventListener("click", async () => {
    const response = await fetch("/downloadPdf", { method: "POST" });
    const blob = await response.blob();

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "forensic_report.pdf";
    a.click();
});
