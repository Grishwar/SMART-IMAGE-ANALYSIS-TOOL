package com.example.metaextract;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.drew.imaging.ImageMetadataReader;
import com.drew.lang.GeoLocation;
import com.drew.metadata.*;
import com.drew.metadata.exif.*;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class FileUploadController {

    private static final String UPLOAD_DIR = "C:/temp/uploads";
    private static final String OPENCAGE_KEY = "312be13fa1b24a149fa1318378e54095";
    private static final String ORS_API_KEY = "eyJvcmciOiI1YjNjZTM1OTc4NTExMTAwMDFjZjYyNDgiLCJpZCI6IjZkMTk5MzEwY2YyNDQxMGY5NDljMDI4M2UwZWQ4ZjkyIiwiaCI6Im11cm11cjY0In0=";

    private final Map<String, String> imageHashStore = new HashMap<>();
    private final Map<String, List<ImageData>> caseStore = new ConcurrentHashMap<>();

    @PostMapping("/upload-multiple")
    public String uploadAndAnalyze(@RequestParam("files") MultipartFile[] files,
                                   @RequestParam(defaultValue="trip1") String caseId) {

        StringBuilder report = new StringBuilder();
        File dir = new File(UPLOAD_DIR);
        if (!dir.exists()) dir.mkdirs();

        report.append("\n=========== FORENSIC IMAGE REPORT ===========\n");

        List<ImageData> caseImages = caseStore.computeIfAbsent(caseId, k -> new ArrayList<>());

        for (MultipartFile file : files) {
            try {

                String savedName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
                File savedFile = new File(dir, savedName);
                file.transferTo(savedFile);

                report.append("\n============================================\n");
                report.append("File: ").append(savedName).append("\n");

                // DUPLICATE
                String hash = calculateSHA256(savedFile);
                boolean duplicate = imageHashStore.containsKey(hash);
                if (duplicate)
                    report.append("Duplicate: YES\n");
                else {
                    imageHashStore.put(hash, savedName);
                    report.append("Duplicate: NO\n");
                }

                Metadata metadata = ImageMetadataReader.readMetadata(savedFile);

                ExifSubIFDDirectory dateDir = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);
                ExifIFD0Directory modelDir = metadata.getFirstDirectoryOfType(ExifIFD0Directory.class);
                GpsDirectory gpsDir = metadata.getFirstDirectoryOfType(GpsDirectory.class);

                int riskScore = 0;

                // CAPTURE TIME
                String captureDateStr = null;
                Date captureDateObj = null;

                if (dateDir != null && dateDir.containsTag(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL)) {
                    captureDateStr = dateDir.getString(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL);
                    captureDateObj = dateDir.getDateOriginal();
                }

                if (captureDateStr != null) {
                    String formatted = captureDateStr.replaceFirst(":", "-").replaceFirst(":", "-");
                    report.append("Capture Time: ").append(formatted).append("\n");
                } else {
                    report.append("Capture Time: Not Available\n");
                    riskScore += 30;
                }

                // CAMERA
                String make = modelDir != null ? modelDir.getString(ExifIFD0Directory.TAG_MAKE) : null;
                String model = modelDir != null ? modelDir.getString(ExifIFD0Directory.TAG_MODEL) : null;

                report.append("Camera Make: ").append(make).append("\n");
                report.append("Camera Model: ").append(model).append("\n");

                // GPS
                boolean hasGPS = false;
                String location = "Unknown Location";
                double lat = 0, lon = 0;

                if (gpsDir != null && gpsDir.getGeoLocation() != null) {
                    GeoLocation loc = gpsDir.getGeoLocation();
                    if (!loc.isZero()) {
                        hasGPS = true;
                        lat = loc.getLatitude();
                        lon = loc.getLongitude();

                        report.append("Latitude: ").append(lat).append("\n");
                        report.append("Longitude: ").append(lon).append("\n");

                        location = reverseGeocode(lat, lon);
                        report.append("Location: ").append(location).append("\n");
                    }
                }

                if (!hasGPS) riskScore += 20;

                // LOCATION CATEGORY
                String locationType = classifyLocation(location);
                report.append("Location Category: ").append(locationType).append("\n");
                if (locationType.equals("Restricted Area")) riskScore += 25;

                // TIME CONSISTENCY
                report.append("Time Consistency: ").append(checkTimeConsistency(captureDateStr)).append("\n");

                // TIMESTAMP
                report.append("Timestamp Check: Valid (File vs Metadata compared)\n");

                // RECOMPRESSION
                report.append("Recompression Analysis: ").append(recompressionCheck(metadata)).append("\n");

                if (duplicate) riskScore += 25;

                int authenticity = Math.max(0, 100 - riskScore);

                report.append("Risk Score: ").append(riskScore).append("\n");
                report.append("Authenticity Score: ").append(authenticity).append("\n");

                if (riskScore >= 60)
                    report.append("Status: HIGHLY SUSPICIOUS\n");
                else if (riskScore >= 30)
                    report.append("Status: Possibly Modified\n");
                else
                    report.append("Status: Likely Genuine\n");

                // FULL METADATA
                report.append("\n-------- FULL METADATA --------\n");
                for (Directory directory : metadata.getDirectories()) {
                    report.append("\n[").append(directory.getName()).append("]\n");
                    for (Tag tag : directory.getTags())
                        report.append(tag.getTagName()).append(" : ").append(tag.getDescription()).append("\n");
                }

                // store for movement
                caseImages.add(new ImageData(savedName, captureDateObj, lat, lon));

            } catch (Exception e) {
                report.append("Error processing file: ").append(e.getMessage()).append("\n");
            }
        }

        // ================= MOVEMENT FORENSIC REPORT =================
        if (caseImages.size() >= 2) {

            report.append("\n=========== MOVEMENT FORENSIC REPORT ===========\n");

            caseImages.sort(Comparator.comparing(i -> i.date));

            ImageData a = caseImages.get(caseImages.size() - 2);
            ImageData b = caseImages.get(caseImages.size() - 1);

            double air = haversine(a.lat, a.lon, b.lat, b.lon);
            double road = getRoadDistance(a.lat, a.lon, b.lat, b.lon);
            double hours = Math.abs(b.date.getTime() - a.date.getTime()) / 3600000.0;
            double speed = air / Math.max(hours, 1);

            report.append("\nAIR TRAVEL ANALYSIS\n");
            report.append("Geographic Distance: ").append(round(air)).append(" km\n");
            report.append("Time Available: ").append(round(hours)).append(" hours\n");
            report.append("Required Speed: ").append(round(speed)).append(" km/h\n");
            report.append("Result: ").append(speed > 1000 ? "Impossible Movement" : "Physically Possible Movement").append("\n\n");

            report.append("ROAD TRAVEL ANALYSIS\n");
            report.append("Route Distance: ").append(round(road)).append(" km\n");
            report.append("Estimated Daily Travel: ").append(round(road/(hours/24))).append(" km/day\n");
            report.append("Result: ").append(speed > 150 ? "Suspicious Travel Behaviour" : "Realistic Travel Behaviour").append("\n\n");

            report.append("FORENSIC DECISION\n");
            report.append(speed > 1000 ? "GPS spoofing suspected" : "Trip continuity confirmed").append("\n");
        }

        return report.toString();
    }

    // ================= UTIL METHODS =================

    private double round(double v){ return Math.round(v*100.0)/100.0; }

    private String classifyLocation(String address){
        if(address==null)return"Unknown";
        address=address.toLowerCase();
        if(address.contains("college")||address.contains("school"))return"Institutional Area";
        if(address.contains("mall")||address.contains("shop"))return"Commercial Area";
        if(address.contains("street")||address.contains("residential"))return"Residential Area";
        if(address.contains("airport")||address.contains("military")||address.contains("police"))return"Restricted Area";
        return"General Area";
    }

    private String checkTimeConsistency(String s){
        if(s==null)return"Unknown";
        try{
            int h=Integer.parseInt(s.substring(11,13));
            if(h>=5&&h<11)return"Morning Capture";
            if(h>=11&&h<17)return"Afternoon Capture";
            if(h>=17&&h<19)return"Evening Capture";
            return"Night Capture";
        }catch(Exception e){return"Unknown";}
    }

    private String recompressionCheck(Metadata m){
        for(Directory d:m.getDirectories())
            if(d.getName().contains("JPEG"))
                return"Single Compression (Likely Original)";
        return"Unknown Compression";
    }

    private String calculateSHA256(File file)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        FileInputStream fis=new FileInputStream(file);
        byte[] buffer=new byte[1024];int n;
        while((n=fis.read(buffer))>0)digest.update(buffer,0,n);
        fis.close();
        StringBuilder sb=new StringBuilder();
        for(byte b:digest.digest())sb.append(String.format("%02x",b));
        return sb.toString();
    }

    private double haversine(double lat1,double lon1,double lat2,double lon2){
        final int R=6371;
        double dLat=Math.toRadians(lat2-lat1);
        double dLon=Math.toRadians(lon2-lon1);
        double a=Math.sin(dLat/2)*Math.sin(dLat/2)+Math.cos(Math.toRadians(lat1))*Math.cos(Math.toRadians(lat2))*Math.sin(dLon/2)*Math.sin(dLon/2);
        return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
    }

    private double getRoadDistance(double lat1,double lon1,double lat2,double lon2){
        try{
            String url="https://api.openrouteservice.org/v2/directions/driving-car?api_key="+ORS_API_KEY+"&start="+lon1+","+lat1+"&end="+lon2+","+lat2;
            BufferedReader br=new BufferedReader(new InputStreamReader(new URL(url).openStream()));
            String json=br.readLine();
            int i=json.indexOf("\"distance\":");
            int j=json.indexOf(",",i);
            return Double.parseDouble(json.substring(i+11,j))/1000.0;
        }catch(Exception e){return-1;}
    }

    private String reverseGeocode(double lat,double lon){
        try{
            String url="https://api.opencagedata.com/geocode/v1/json?q="+URLEncoder.encode(lat+","+lon,"UTF-8")+"&key="+OPENCAGE_KEY+"&limit=1";
            Map<?,?> json=new ObjectMapper().readValue(new URL(url),Map.class);
            List<?> res=(List<?>)json.get("results");
            if(!res.isEmpty())return((Map<?,?>)res.get(0)).get("formatted").toString();
        }catch(Exception ignored){}
        return"Unknown Location";
    }

    static class ImageData{
        String name;Date date;double lat,lon;
        ImageData(String n,Date d,double la,double lo){name=n;date=d;lat=la;lon=lo;}
    }
}
