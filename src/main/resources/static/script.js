document.addEventListener("DOMContentLoaded", function(){

let map = L.map('map').setView([20,78],5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

let markers=[];
let lastLocations=[];
let metadataStore={};
let elaStore={};
let fileNameStore={};
let thumbnailStore={};
let lastReportText="";

function clearMap(){
    markers.forEach(m=>map.removeLayer(m));
    markers=[];
    lastLocations=[];
}

// ================= ANALYZE =================
document.getElementById("analyzeBtn").onclick = async function(){
    const files=document.getElementById("files").files;
    if(files.length===0){ alert("Select images first"); return; }

    document.getElementById("loading").style.display="block";
    clearMap();
    metadataStore={};
    elaStore={};
    fileNameStore={};

    // Store thumbnail URLs from uploaded files BEFORE sending to server
    for(let f of files){
        thumbnailStore[f.name] = URL.createObjectURL(f);
    }

    let formData=new FormData();
    for(let f of files) formData.append("files",f);

    const res=await fetch("/analyze",{method:"POST",body:formData});
    const text=await res.text();

    lastReportText=text;
    document.getElementById("loading").style.display="none";
    parseReport(text);
};

// ================= MOVEMENT =================
document.getElementById("movementBtn").onclick=function(){
    if(!lastReportText.includes("MOVEMENT FORENSIC REPORT")){
        alert("Upload minimum 2 GPS images");
        return;
    }
    const movement=lastReportText.split("=========== MOVEMENT FORENSIC REPORT ===========")[1];
    alert("FORENSIC MOVEMENT ANALYSIS\n\n"+movement);
};

// ================= PARSER =================
function parseReport(report){
    const rows=document.querySelector("#resultTable tbody");
    rows.innerHTML="";

    const blocks=report.split("============================================");

    blocks.forEach(block=>{
        if(!block.includes("File:")) return;

        let file=getValue(block,"File:");
        let risk=getValue(block,"Risk Score:");
        let auth=getValue(block,"Authenticity Score:");
        let status=getLine(block,"Status:");
        let location=getLine(block,"Location:");
        let area=getLine(block,"Area Classification:");
        let lat=getValue(block,"Latitude:");
        let lon=getValue(block,"Longitude:");
        let elaResult=getLine(block,"ELA Result:");

        // Extract AI summary
        let aiSummaryMatch = block.match(/----- AI FORENSIC SUMMARY -----\n([\s\S]*?)(?=\n-{3,}|\n={3,}|$)/);
        let aiSummary = aiSummaryMatch ? aiSummaryMatch[1].trim() : "";

        // Extract ELA base64
        let elaBase64Match = block.match(/ELA_IMAGE_BASE64:\s*([^\n]+)/);
        if(elaBase64Match) elaStore[file] = elaBase64Match[1].trim();

        metadataStore[file] = formatMetadata(block);
        fileNameStore[file] = file;

        // Colors
        let elaColor = "#00ffd0";
        if(elaResult.includes("HIGH")) elaColor = "#ff4444";
        else if(elaResult.includes("MEDIUM")) elaColor = "#ffaa00";
        else if(elaResult.includes("LOW")) elaColor = "#00ff88";

        let statusColor = "#00ff88";
        if(status.includes("SUSPICIOUS")) statusColor = "#ff4444";
        else if(status.includes("Possibly")) statusColor = "#ffaa00";

        // Find thumbnail - server adds timestamp prefix to filename
        // Match by checking if stored filename is contained in server filename
        let thumbUrl = "";
        for(let origName in thumbnailStore){
            if(file.includes(origName)){
                thumbUrl = thumbnailStore[origName];
                break;
            }
        }

        let tr=document.createElement("tr");
        tr.innerHTML=`
        <td>
            ${thumbUrl ? `<img src="${thumbUrl}" style="width:70px;height:70px;object-fit:cover;border-radius:6px;border:2px solid #00d9ff;display:block;margin-bottom:5px;">` : ''}
            <span style="font-size:11px;word-break:break-all">${file}</span>
        </td>
        <td>${risk}</td>
        <td>${auth}</td>
        <td style="color:${statusColor};font-weight:bold">${status}</td>
        <td>${location}<br><b style="color:#00ffd0">${area}</b><br>${lat}, ${lon}</td>
        <td style="color:${elaColor};font-weight:bold">${elaResult||'N/A'}</td>
        <td>
            <button onclick="viewMetadata('${file}')">View Metadata</button>
            ${elaStore[file] ? `<button onclick="viewELA('${file}')" style="background:linear-gradient(45deg,#ff4444,#ff8800)">View ELA</button>` : ''}
            <button onclick="viewAISummary('${file}')" style="background:linear-gradient(45deg,#7b2ff7,#00d9ff)">AI Summary</button>
        </td>`;
        rows.appendChild(tr);

        if(lat && lon){
            lat=parseFloat(lat); lon=parseFloat(lon);
            if(!isNaN(lat)&&!isNaN(lon)){
                lastLocations.push([lat,lon]);
                let marker=L.marker([lat,lon]).addTo(map).bindPopup(file);
                markers.push(marker);
            }
        }
    });

    if(lastLocations.length>=2){
        let line=L.polyline(lastLocations,{color:'red'}).addTo(map);
        map.fitBounds(line.getBounds());
        document.getElementById("routeBtn").style.display="inline-block";
    }
}

// ================= VIEW METADATA =================
window.viewMetadata=function(file){
    document.getElementById("metadataContent").innerHTML=metadataStore[file];
    document.getElementById("modalTitle").innerText="Metadata — " + file;
    document.getElementById("elaSection").style.display="none";
    document.getElementById("aiSection").style.display="none";
    document.getElementById("metadataModal").style.display="block";
}

// ================= VIEW ELA =================
window.viewELA=function(file){
    let base64=elaStore[file];
    if(!base64){ alert("ELA image not available"); return; }

    document.getElementById("modalTitle").innerText="ELA Analysis — " + file;
    document.getElementById("metadataContent").innerHTML=
        "<p style='color:#333;font-family:Consolas'>" +
        "<b>ELA = Error Level Analysis</b><br><br>" +
        "Bright/Red areas = HIGH pixel difference = possibly tampered<br>" +
        "Dark/Black areas = LOW pixel difference = likely original pixels<br><br>" +
        "Original image pixels vs re-compressed pixels are compared.<br>" +
        "Edited regions show higher error levels than surrounding areas." +
        "</p>";

    document.getElementById("elaImage").src="data:image/png;base64,"+base64;
    document.getElementById("elaSection").style.display="block";
    document.getElementById("aiSection").style.display="none";
    document.getElementById("metadataModal").style.display="block";
}

// ================= VIEW AI SUMMARY =================
window.viewAISummary=async function(file){
    document.getElementById("modalTitle").innerText="AI Forensic Summary — " + file;
    document.getElementById("metadataContent").innerHTML="";
    document.getElementById("elaSection").style.display="none";

    // Show loading
    document.getElementById("aiSummaryText").innerHTML=
        "<i>Generating AI summary... please wait...</i>";
    document.getElementById("aiSection").style.display="block";
    document.getElementById("metadataModal").style.display="block";

    try {
        const res=await fetch("/aiSummary",{
            method:"POST",
            headers:{"Content-Type":"application/x-www-form-urlencoded"},
            body:"fileName="+encodeURIComponent(file)
        });
        const text=await res.text();
        document.getElementById("aiSummaryText").innerHTML=
            text.replace(/\n/g,"<br>");
    } catch(e) {
        document.getElementById("aiSummaryText").innerHTML=
            "Error fetching AI summary: "+e.message;
    }
}

window.closeModal=function(){
    document.getElementById("metadataModal").style.display="none";
}

// ================= PDF =================
document.getElementById("pdfBtn").onclick = async function(){
    const type=document.getElementById("reportType").value;
    const caseNo=document.getElementById("caseNo").value;
    const officer=document.getElementById("officer").value;
    const department=document.getElementById("department").value;

    const res=await fetch(
        `/downloadPdf?type=${type}&caseNo=${encodeURIComponent(caseNo)}&officer=${encodeURIComponent(officer)}&department=${encodeURIComponent(department)}`,
        {method:"POST"}
    );
    const blob=await res.blob();
    const url=window.URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=type==="court"?"Court_Report.pdf":"Full_Metadata_Report.pdf";
    a.click();
};

// ================= ROUTE BUTTON =================
document.getElementById("routeBtn").onclick=function(){
    if(lastLocations.length<1){ alert("No GPS coordinates found"); return; }
    let url="";
    if(lastLocations.length===1){
        url=`https://www.google.com/maps?q=${lastLocations[0][0]},${lastLocations[0][1]}`;
    } else {
        let s=lastLocations[0], e=lastLocations[lastLocations.length-1];
        url=`https://www.google.com/maps/dir/${s[0]},${s[1]}/${e[0]},${e[1]}`;
    }
    window.open(url,"_blank");
};

// ================= HELPERS =================
function getValue(text,label){
    let m=text.match(new RegExp(label+"\\s*(.*)"));
    return m?m[1].trim():"";
}
function getLine(text,label){
    let m=text.match(new RegExp(label+"\\s*(.*)"));
    return m?m[1].trim():"";
}
function formatMetadata(text){
    let fields=["File:","SHA256:","Capture Time:","Camera:","Latitude:","Longitude:","Location:",
    "Area Classification:","Risk Score:","Authenticity Score:","Status:","File Size:",
    "Dimensions:","GPS Present:","Software Tag:","MakerNote Present:","Thumbnail DateTime:",
    "Thumbnail Date Match:","Megapixels","EXIF Timezone Offset:","Expected Timezone",
    "Total Suspicion Indicators:","No tampering indicators","ELA Result:",
    "AIR DISTANCE:","ROAD DISTANCE:","AVG SPEED:","MOVEMENT TYPE:","Time Gap:"];
    let out="";
    text.split("\n").forEach(l=>{
        if(l.startsWith("ELA_IMAGE_BASE64:")) return;
        if(l.includes("AI FORENSIC SUMMARY")) return;
        fields.forEach(f=>{ if(l.includes(f)) out+=l+"<br>"; });
        if(l.trim().startsWith("[")) out+=`<span style="color:red">${l}</span><br>`;
        if(l.trim().startsWith("- ")) out+=`<span style="color:orange">${l}</span><br>`;
    });
    return out;
}

});