document.addEventListener("DOMContentLoaded", function(){

let map = L.map('map').setView([20,78],5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

let markers=[];
let lastLocations=[];
let metadataStore={};
let lastReportText="";

function clearMap(){
    markers.forEach(m=>map.removeLayer(m));
    markers=[];
    lastLocations=[];
}

// ================= ANALYZE =================
document.getElementById("analyzeBtn").onclick = async function(){

    const files=document.getElementById("files").files;
    if(files.length===0){
        alert("Select images first");
        return;
    }

    document.getElementById("loading").style.display="block";
    clearMap();
    metadataStore={};

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

    const movement = lastReportText.split("=========== MOVEMENT FORENSIC REPORT ===========")[1];
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

        metadataStore[file]=formatMetadata(block);

        let tr=document.createElement("tr");
        tr.innerHTML=`
        <td>${file}</td>
        <td>${risk}</td>
        <td>${auth}</td>
        <td>${status}</td>
        <td>${location}<br><b style="color:#00ffd0">${area}</b><br>${lat}, ${lon}</td>
        <td><button onclick="viewMetadata('${file}')">View Metadata</button></td>`;
        rows.appendChild(tr);

        if(lat && lon){
            lat=parseFloat(lat);
            lon=parseFloat(lon);
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

// ================= METADATA =================
window.viewMetadata=function(file){
    document.getElementById("metadataContent").innerHTML=metadataStore[file];
    document.getElementById("metadataModal").style.display="block";
}

window.closeModal=function(){
    document.getElementById("metadataModal").style.display="none";
}

// ================= PDF =================
document.getElementById("pdfBtn").onclick = async function(){

    const type = document.getElementById("reportType").value;
    const caseNo = document.getElementById("caseNo").value;
    const officer = document.getElementById("officer").value;
    const department = document.getElementById("department").value;

    const res = await fetch(
        `/downloadPdf?type=${type}&caseNo=${encodeURIComponent(caseNo)}&officer=${encodeURIComponent(officer)}&department=${encodeURIComponent(department)}`,
        {method:"POST"}
    );

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = type==="court" ? "Court_Report.pdf" : "Full_Metadata_Report.pdf";
    a.click();
};
// ================= OPEN ROUTE BUTTON =================
document.getElementById("routeBtn").onclick = function(){

    if(lastLocations.length < 1){
        alert("No GPS coordinates found in images");
        return;
    }

    let url="";

    if(lastLocations.length === 1){
        let lat=parseFloat(lastLocations[0][0]);
        let lon=parseFloat(lastLocations[0][1]);
        url=`https://www.google.com/maps?q=${lat},${lon}`;
    }
    else{
        let startLat=parseFloat(lastLocations[0][0]);
        let startLon=parseFloat(lastLocations[0][1]);
        let endLat=parseFloat(lastLocations[lastLocations.length-1][0]);
        let endLon=parseFloat(lastLocations[lastLocations.length-1][1]);

        url=`https://www.google.com/maps/dir/${startLat},${startLon}/${endLat},${endLon}`;
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
    "Dimensions:","GPS Present:","AIR DISTANCE:","ROAD DISTANCE:","AVG SPEED:","MOVEMENT TYPE:","Time Gap:"];
    let out="";
    text.split("\n").forEach(l=>{
        fields.forEach(f=>{
            if(l.includes(f)) out+=l+"<br>";
        });
    });
    return out;
}

});