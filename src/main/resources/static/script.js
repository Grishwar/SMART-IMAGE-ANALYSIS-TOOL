let map = L.map('map').setView([20,78],5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

let markers=[];
let lastLocations=[];
let metadataStore={};

function clearMap(){
    markers.forEach(m=>map.removeLayer(m));
    markers=[];
    lastLocations=[];
}

document.getElementById("analyzeBtn").onclick = async () => {

    const files=document.getElementById("files").files;
    if(files.length===0) return alert("Select images first");

    document.getElementById("loading").style.display="block";
    clearMap();
    metadataStore={};

    let formData=new FormData();
    for(let f of files) formData.append("files",f);

    const res=await fetch("/analyze",{method:"POST",body:formData});
    const text=await res.text();

    document.getElementById("loading").style.display="none";

    parseReport(text);
};

function parseReport(report){

    const rows=document.querySelector("#resultTable tbody");
    rows.innerHTML="";
    document.getElementById("movement").innerHTML="";

    const blocks=report.split("============================================");

    blocks.forEach(block=>{

        if(!block.includes("File:")) return;

        let file=getValue(block,"File:");
        let risk=getValue(block,"Risk Score:");
        let auth=getValue(block,"Authenticity Score:");
        let status=getLine(block,"Status:");
        let location=getLine(block,"Location:");
        let lat=getValue(block,"Latitude:");
        let lon=getValue(block,"Longitude:");

        metadataStore[file]=block;

        let tr=document.createElement("tr");
        tr.innerHTML=`
            <td>${file}</td>
            <td>${risk}</td>
            <td>${auth}</td>
            <td>${status}</td>
            <td>${location}<br>${lat}, ${lon}</td>
            <td><button onclick="viewMetadata('${file}')">View Metadata</button></td>
        `;
        rows.appendChild(tr);

        if(lat && lon){
            lat=parseFloat(lat); lon=parseFloat(lon);
            lastLocations.push([lat,lon]);

            let marker=L.marker([lat,lon]).addTo(map)
                .bindPopup(file+"<br>"+location);
            markers.push(marker);
        }
    });

    if(lastLocations.length>=2){
        let line=L.polyline(lastLocations,{color:'red'}).addTo(map);
        map.fitBounds(line.getBounds());
        document.getElementById("routeBtn").style.display="inline-block";
    }
    else if(lastLocations.length==1){
        map.setView(lastLocations[0],13);
        document.getElementById("routeBtn").style.display="inline-block";
    }
}

function viewMetadata(file){
    document.getElementById("metadataContent").textContent = metadataStore[file];
    document.getElementById("metadataModal").style.display="block";
}

function closeModal(){
    document.getElementById("metadataModal").style.display="none";
}

function getValue(text,label){
    let m=text.match(new RegExp(label+"\\s*(.*)"));
    return m?m[1].trim():"";
}
function getLine(text,label){
    let m=text.match(new RegExp(label+"\\s*(.*)"));
    return m?m[1]:"";
}

document.getElementById("routeBtn").onclick=()=>{
    if(lastLocations.length==0) return;

    if(lastLocations.length==1){
        const [lat,lon]=lastLocations[0];
        window.open(`https://www.google.com/maps?q=${lat},${lon}`,'_blank');
    }
    else{
        const start=lastLocations[0];
        const end=lastLocations[lastLocations.length-1];
        window.open(`https://www.google.com/maps/dir/${start[0]},${start[1]}/${end[0]},${end[1]}`,'_blank');
    }
};

document.getElementById("pdfBtn").onclick=async()=>{

    const type=document.getElementById("reportType").value;

    const res=await fetch("/downloadPdf?type="+type,{method:"POST"});
    const blob=await res.blob();

    const url=window.URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download="Forensic_Report.pdf";
    a.click();
};