package com.example.metaextract;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.drew.imaging.ImageMetadataReader;
import com.drew.lang.GeoLocation;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import com.drew.metadata.exif.ExifIFD0Directory;
import com.drew.metadata.exif.ExifSubIFDDirectory;
import com.drew.metadata.exif.GpsDirectory;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

@RestController
public class FileUploadController {


    private static final String UPLOAD_DIR =
            System.getProperty("user.home") + File.separator + "metaextract_uploads";

    private static final String OPENCAGE_KEY = "312be13fa1b24a149fa1318378e54095";
    private static final String ORS_KEY = "eyJvcmciOiI1YjNjZTM1OTc4NTExMTAwMDFjZjYyNDgiLCJpZCI6IjZkMTk5MzEwY2YyNDQxMGY5NDljMDI4M2UwZWQ4ZjkyIiwiaCI6Im11cm11cjY0In0=";

    private String lastFullReport="";
    private String lastCourtReport="";

    // ========================= ANALYZE =========================
    @PostMapping("/analyze")
    public String analyze(@RequestParam("files") MultipartFile[] files){

        StringBuilder report=new StringBuilder();
        report.append("\n=========== FORENSIC IMAGE REPORT ===========\n");

        File dir=new File(UPLOAD_DIR);
        if(!dir.exists()) dir.mkdirs();

        List<ImageData> movement=new ArrayList<>();
        Set<String> hashes=new HashSet<>();

        for(MultipartFile file:files){
            try{
                if(file.isEmpty()) continue;

                String name=System.currentTimeMillis()+"_"+file.getOriginalFilename();
                File saved=new File(dir,name);
                file.transferTo(saved);

                report.append("\n============================================\n");
                report.append("File: ").append(name).append("\n");

                // -------- HASH --------
                String hash=sha256(saved);
                if(hashes.contains(hash)){
                    report.append("Duplicate: YES\n");
                }else{
                    hashes.add(hash);
                    report.append("Duplicate: NO\n");
                }
                report.append("SHA256: ").append(hash).append("\n");

                Metadata metadata=ImageMetadataReader.readMetadata(saved);

                ExifSubIFDDirectory dateDir=metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);
                ExifIFD0Directory camDir=metadata.getFirstDirectoryOfType(ExifIFD0Directory.class);
                GpsDirectory gps=metadata.getFirstDirectoryOfType(GpsDirectory.class);

                int risk=0;
                Date captureDate=null;

                // -------- TIMESTAMP --------
                if(dateDir!=null && dateDir.getDateOriginal()!=null){
                    captureDate=dateDir.getDateOriginal();
                    report.append("Capture Time: ").append(captureDate).append("\n");
                }else{
                    report.append("Capture Time: Not Available\n");
                    risk+=30;
                }

                // -------- CAMERA --------
                String make=camDir!=null?camDir.getString(ExifIFD0Directory.TAG_MAKE):"Unknown";
                String model=camDir!=null?camDir.getString(ExifIFD0Directory.TAG_MODEL):"Unknown";
                report.append("Camera: ").append(make).append(" ").append(model).append("\n");

                // -------- GPS --------
                double lat=0,lon=0;
                boolean hasGPS=false;
                String location="Unknown Location";

                if(gps!=null){
                    GeoLocation g=gps.getGeoLocation();
                    if(g!=null && !g.isZero()){
                        hasGPS=true;
                        lat=g.getLatitude();
                        lon=g.getLongitude();
                        location=reverseGeocode(lat,lon);

                        report.append("Latitude: ").append(lat).append("\n");
                        report.append("Longitude: ").append(lon).append("\n");
                    }else{
                        risk+=20;
                    }
                }else{
                    risk+=20;
                }

                report.append("Location: ").append(location).append("\n");
                report.append("Area Classification: ").append(classifyArea(location)).append("\n");

                // -------- AUTHENTICITY --------
                int authenticity=Math.max(0,100-risk);
                report.append("Risk Score: ").append(risk).append("\n");
                report.append("Authenticity Score: ").append(authenticity).append("\n");
                report.append(authenticity<40?"Status: HIGHLY SUSPICIOUS\n":
                        authenticity<70?"Status: Possibly Modified\n":
                                "Status: Likely Genuine\n");

                report.append("\n----- FORENSIC SUMMARY -----\n");
                report.append("File Size: ").append(saved.length()/1024).append(" KB\n");
                report.append("Dimensions: ").append(getDimensions(metadata)).append("\n");
                report.append("GPS Present: ").append(hasGPS?"YES":"NO").append("\n");

                if(hasGPS && captureDate!=null)
                    movement.add(new ImageData(captureDate,lat,lon));

            }catch(Exception e){
                e.printStackTrace();
                report.append("Error processing file\n");
            }
        }

        if(movement.size()>=2)
            report.append(generateMovement(movement));

        lastFullReport=report.toString();
        lastCourtReport="DIGITAL COURT ADMISSIBLE FORENSIC REPORT\n\n"+lastFullReport;

        return lastFullReport;
    }

    // ================= MOVEMENT =================
    private String generateMovement(List<ImageData> list){

        list.sort(Comparator.comparing((ImageData i)->i.date));

        ImageData a=list.get(0);
        ImageData b=list.get(list.size()-1);

        double hours=Math.abs(b.date.getTime()-a.date.getTime())/3600000.0;
        double days=hours/24.0;

        double air=haversine(a.lat,a.lon,b.lat,b.lon);
        double road=getRoadDistance(a.lat,a.lon,b.lat,b.lon);
        double speed=road/Math.max(hours,1);

        StringBuilder r=new StringBuilder("\n=========== MOVEMENT FORENSIC REPORT ===========\n");

        r.append("FROM: ").append(a.date).append("\n");
        r.append("TO: ").append(b.date).append("\n");
        r.append("Time Gap: ").append(round(hours)).append(" hrs (").append(round(days)).append(" days)\n\n");
        r.append("AIR DISTANCE: ").append(round(air)).append(" km\n");
        r.append("ROAD DISTANCE: ").append(round(road)).append(" km\n");
        r.append("AVG SPEED: ").append(round(speed)).append(" km/h\n");
        r.append("MOVEMENT TYPE: ").append(classifyMovement(speed)).append("\n");

        return r.toString();
    }

    private double getRoadDistance(double lat1,double lon1,double lat2,double lon2){
        try{
            String url="https://api.openrouteservice.org/v2/directions/driving-car?api_key="+ORS_KEY+
                    "&start="+lon1+","+lat1+"&end="+lon2+","+lat2;

            Map<?,?> json=new ObjectMapper().readValue(new URL(url),Map.class);
            Map<?,?> feature=(Map<?,?>)((List<?>)json.get("features")).get(0);
            Map<?,?> summary=(Map<?,?>)((Map<?,?>)feature.get("properties")).get("summary");

            return ((Number)summary.get("distance")).doubleValue()/1000.0;

        }catch(Exception e){return 0;}
    }

    // ================= PDF =================
    // ================= PDF GENERATION =================
    @PostMapping("/downloadPdf")
    public void downloadPdf(@RequestParam String type,
                            @RequestParam(required = false) String caseNo,
                            @RequestParam(required = false) String officer,
                            @RequestParam(required = false) String department,
                            HttpServletResponse response) throws Exception {

        response.setContentType("application/pdf");

        String fileName = type.equals("court") ?
                "Court_Investigation_Report.pdf" :
                "Full_Metadata_Report.pdf";

        response.setHeader("Content-Disposition",
                "attachment; filename=" + fileName);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document();
        PdfWriter.getInstance(document, baos);
        document.open();

        if(type.equals("court")){

            // ===== COURT REPORT FORMAT =====
            document.add(new Paragraph("DIGITAL FORENSIC COURT EVIDENCE REPORT"));
            document.add(new Paragraph("------------------------------------------------------------"));
            document.add(new Paragraph("Case Number: " + safe(caseNo)));
            document.add(new Paragraph("Investigating Officer: " + safe(officer)));
            document.add(new Paragraph("Department: " + safe(department)));
            document.add(new Paragraph("Report Generated On: " + new Date()));
            document.add(new Paragraph("\n"));

            document.add(new Paragraph("EVIDENCE SUMMARY"));
            document.add(new Paragraph("------------------------------------------------------------"));
            document.add(new Paragraph("\n"));

            for(String line : lastFullReport.split("\n")){
                if(line.contains("File:") ||
                        line.contains("SHA256:") ||
                        line.contains("Capture Time:") ||
                        line.contains("Location:") ||
                        line.contains("Area Classification:") ||
                        line.contains("Risk Score:") ||
                        line.contains("Authenticity Score:") ||
                        line.contains("Status:") ||
                        line.contains("AIR DISTANCE:") ||
                        line.contains("ROAD DISTANCE:") ||
                        line.contains("AVG SPEED:") ||
                        line.contains("MOVEMENT TYPE:") ||
                        line.contains("Time Gap:"))
                {
                    document.add(new Paragraph(line));
                }
            }

            document.add(new Paragraph("\n"));
            document.add(new Paragraph("DECLARATION"));
            document.add(new Paragraph("------------------------------------------------------------"));
            document.add(new Paragraph(
                    "I hereby certify that the above digital evidence was analyzed " +
                            "using MetaExtract Digital Forensic Engine and the findings " +
                            "are true to the best of my knowledge."));
            document.add(new Paragraph("\n"));
            document.add(new Paragraph("Signature: __________________________"));
            document.add(new Paragraph("Date: _______________________________"));

        } else {

            // ===== FULL METADATA REPORT =====
            document.add(new Paragraph("FULL DIGITAL FORENSIC METADATA REPORT"));
            document.add(new Paragraph("------------------------------------------------------------"));
            document.add(new Paragraph("Generated On: " + new Date()));
            document.add(new Paragraph("\n"));

            for(String line : lastFullReport.split("\n")){
                document.add(new Paragraph(line));
            }
        }

        document.close();
        response.getOutputStream().write(baos.toByteArray());
        response.getOutputStream().flush();
    }

    // ================= HELPERS =================
    private String reverseGeocode(double lat,double lon){
        try{
            String url="https://api.opencagedata.com/geocode/v1/json?q="+URLEncoder.encode(lat+","+lon,"UTF-8")+"&key="+OPENCAGE_KEY;
            Map<?,?> json=new ObjectMapper().readValue(new URL(url),Map.class);
            List<?> res=(List<?>)json.get("results");
            if(!res.isEmpty()) return ((Map<?,?>)res.get(0)).get("formatted").toString();
        }catch(Exception ignored){}
        return "Unknown Location";
    }

    private String classifyMovement(double speed){
        if(speed>900) return "Impossible Movement (Metadata Tampered)";
        if(speed>300) return "Flight Travel";
        if(speed>120) return "Vehicle Travel";
        if(speed>15) return "Human Movement";
        return "Natural Movement";
    }

    private String classifyArea(String loc){
        if(loc==null) return "Unknown";
        String t=loc.toLowerCase();
        if(t.contains("college")||t.contains("school")) return "Educational Institution";
        if(t.contains("hospital")) return "Medical Facility";
        if(t.contains("police")||t.contains("court")) return "Restricted Area";
        if(t.contains("mall")||t.contains("market")) return "Commercial Area";
        if(t.contains("colony")||t.contains("residential")) return "Residential Area";
        if(t.contains("park")||t.contains("lake")||t.contains("beach")) return "Public Area";
        return "General Area";
    }

    private String sha256(File f)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");
        FileInputStream fis=new FileInputStream(f);
        byte[] b=new byte[1024]; int n;
        while((n=fis.read(b))>0)d.update(b,0,n);
        fis.close();
        StringBuilder s=new StringBuilder();
        for(byte bb:d.digest())s.append(String.format("%02x",bb));
        return s.toString();
    }

    private double haversine(double la1,double lo1,double la2,double lo2){
        final int R=6371;
        double dLat=Math.toRadians(la2-la1), dLon=Math.toRadians(lo2-lo1);
        double a=Math.sin(dLat/2)*Math.sin(dLat/2)+Math.cos(Math.toRadians(la1))*Math.cos(Math.toRadians(la2))*Math.sin(dLon/2)*Math.sin(dLon/2);
        return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
    }

    private double round(double v){ return Math.round(v*100.0)/100.0; }

    private String getDimensions(Metadata metadata){
        try{
            for(Directory d:metadata.getDirectories()){
                for(Tag t:d.getTags()){
                    if(t.getTagName().equalsIgnoreCase("Image Width"))
                        return t.getDescription();
                }
            }
        }catch(Exception ignored){}
        return "Not Available";
    }
    private String safe(String value){
        return value == null ? "Not Provided" : value;
    }

    static class ImageData{
        Date date; double lat,lon;
        ImageData(Date d,double la,double lo){date=d;lat=la;lon=lo;}
    }

}
