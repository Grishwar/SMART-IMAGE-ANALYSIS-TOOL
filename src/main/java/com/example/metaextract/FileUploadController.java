package com.example.metaextract;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

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
import com.drew.metadata.exif.ExifThumbnailDirectory;
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

    private String lastFullReport = "";
    private String lastCourtReport = "";

    // ========================= ANALYZE =========================
    @PostMapping("/analyze")
    public String analyze(@RequestParam("files") MultipartFile[] files) {

        StringBuilder report = new StringBuilder();
        report.append("\n=========== FORENSIC IMAGE REPORT ===========\n");

        File dir = new File(UPLOAD_DIR);
        if (!dir.exists()) dir.mkdirs();

        List<ImageData> movement = new ArrayList<>();
        Set<String> hashes = new HashSet<>();

        for (MultipartFile file : files) {
            try {
                if (file.isEmpty()) continue;

                String name = System.currentTimeMillis() + "_" + file.getOriginalFilename();
                File saved = new File(dir, name);
                file.transferTo(saved);

                report.append("\n============================================\n");
                report.append("File: ").append(name).append("\n");

                // -------- HASH --------
                String hash = sha256(saved);
                if (hashes.contains(hash)) {
                    report.append("Duplicate: YES\n");
                } else {
                    hashes.add(hash);
                    report.append("Duplicate: NO\n");
                }
                report.append("SHA256: ").append(hash).append("\n");

                Metadata metadata = ImageMetadataReader.readMetadata(saved);

                ExifSubIFDDirectory dateDir = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);
                ExifIFD0Directory camDir = metadata.getFirstDirectoryOfType(ExifIFD0Directory.class);
                GpsDirectory gps = metadata.getFirstDirectoryOfType(GpsDirectory.class);
                ExifThumbnailDirectory thumbDir = metadata.getFirstDirectoryOfType(ExifThumbnailDirectory.class);

                int risk = 0;
                List<String> suspicions = new ArrayList<>();

                Date captureDate = null;
                String captureDateStr = "Not Available";

                // -------- TIMESTAMP --------
                String offsetTimeOriginal = null;
                if (dateDir != null) {
                    offsetTimeOriginal = dateDir.getString(0x9011);
                    if (offsetTimeOriginal == null)
                        offsetTimeOriginal = dateDir.getString(0x9010);
                }

                if (dateDir != null) {
                    if (offsetTimeOriginal != null && !offsetTimeOriginal.isEmpty()) {
                        TimeZone tz = parseTimezone(offsetTimeOriginal);
                        captureDate = dateDir.getDateOriginal(tz);
                    } else {
                        String rawDateTime = dateDir.getString(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL);
                        if (rawDateTime != null && !rawDateTime.isEmpty()) {
                            captureDate = parseExifDateTime(rawDateTime);
                            captureDateStr = formatDateLocal(rawDateTime);
                        }
                    }

                    if (captureDate != null && captureDateStr.equals("Not Available")) {
                        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss a");
                        if (offsetTimeOriginal != null) {
                            TimeZone tz = parseTimezone(offsetTimeOriginal);
                            sdf.setTimeZone(tz);
                            captureDateStr = sdf.format(captureDate) + " " + offsetTimeOriginal;
                        } else {
                            sdf.setTimeZone(TimeZone.getDefault());
                            captureDateStr = sdf.format(captureDate) + " (device local time)";
                        }
                    }
                }

                if (captureDate == null && camDir != null) {
                    String rawDateTime = camDir.getString(ExifIFD0Directory.TAG_DATETIME);
                    if (rawDateTime != null && !rawDateTime.isEmpty()) {
                        captureDate = parseExifDateTime(rawDateTime);
                        captureDateStr = formatDateLocal(rawDateTime) + " (file modification time)";
                    }
                }

                if (captureDate != null) {
                    report.append("Capture Time: ").append(captureDateStr).append("\n");
                } else {
                    report.append("Capture Time: Not Available\n");
                    risk += 30;
                    suspicions.add("Capture timestamp is missing — possible metadata wipe");
                }

                // -------- CAMERA --------
                String make = camDir != null ? camDir.getString(ExifIFD0Directory.TAG_MAKE) : "Unknown";
                String model = camDir != null ? camDir.getString(ExifIFD0Directory.TAG_MODEL) : "Unknown";
                report.append("Camera: ").append(make).append(" ").append(model).append("\n");

                // ======================================================
                // CHECK 1: SOFTWARE TAG
                // Detects if ExifTool, Photoshop, GIMP etc. edited the file
                // ======================================================
                String software = camDir != null ? camDir.getString(ExifIFD0Directory.TAG_SOFTWARE) : null;
                report.append("Software Tag: ").append(software != null ? software : "Not Present").append("\n");

                if (software != null) {
                    String sw = software.toLowerCase();

                    boolean isGenuineCameraApp = sw.contains("mediatek") ||
                            sw.contains("camera application") ||
                            sw.contains("camera2") ||
                            sw.contains("gcam") ||
                            sw.contains("miui") ||
                            sw.contains("samsung camera") ||
                            sw.contains("pixel camera") ||
                            sw.contains("iphone") ||
                            sw.contains("apple");

                    if (isGenuineCameraApp) {
                        risk += 0;
                        report.append("Software Note: " + software + " (Genuine camera app)\n");
                    } else if (sw.contains("exiftool")) {
                        risk += 40;
                        suspicions.add("ExifTool detected in Software tag — metadata was edited using ExifTool");
                    } else if (sw.contains("photoshop")) {
                        risk += 40;
                        suspicions.add("Adobe Photoshop detected in Software tag — image may be edited");
                    } else if (sw.contains("gimp")) {
                        risk += 35;
                        suspicions.add("GIMP detected in Software tag — image may be edited");
                    } else if (sw.contains("lightroom")) {
                        risk += 30;
                        suspicions.add("Adobe Lightroom detected in Software tag — image was post-processed");
                    } else if (sw.contains("paint") || sw.contains("snapseed") || sw.contains("pixlr")) {
                        risk += 25;
                        suspicions.add("Photo editing app (" + software + ") detected in Software tag");
                    }
                } else {
                    risk += 5;
                    report.append("Software Note: Not present — metadata may have been stripped\n");
                }

                // ======================================================
                // CHECK 2: THUMBNAIL DATE vs ORIGINAL DATE
                // If someone edits the timestamp, thumbnail date often stays old
                // ======================================================
                if (thumbDir != null && dateDir != null) {
                    String thumbDateTime = thumbDir.getString(ExifThumbnailDirectory.TAG_DATETIME);
                    String origDateTime = dateDir.getString(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL);

                    report.append("Thumbnail DateTime: ").append(thumbDateTime != null ? thumbDateTime : "Not Present").append("\n");

                    if (thumbDateTime != null && origDateTime != null) {
                        if (!thumbDateTime.trim().equals(origDateTime.trim())) {
                            risk += 35;
                            suspicions.add("THUMBNAIL DATE MISMATCH — Thumbnail shows (" + thumbDateTime +
                                    ") but Original shows (" + origDateTime +
                                    ") — strong sign of timestamp tampering");
                        } else {
                            report.append("Thumbnail Date Match: YES (consistent)\n");
                        }
                    } else if (thumbDateTime == null && origDateTime != null) {
                        // just report, don't add to suspicion list
                        report.append("Thumbnail Note: Missing — normal for Android devices\n");
                    }
                } else {
                    report.append("Thumbnail DateTime: Not Available\n");
                }

                // ======================================================
                // CHECK 3: MAKERNOTE CHECK
                // Every real camera embeds a MakerNote. If camera brand is set
                // but MakerNote is missing, model was likely faked.
                // ======================================================
                boolean hasMakerNote = false;
                for (Directory d : metadata.getDirectories()) {
                    String dirName = d.getName().toLowerCase();
                    if (dirName.contains("makernote") || dirName.contains("maker note")) {
                        hasMakerNote = true;
                        break;
                    }
                }
                report.append("MakerNote Present: ").append(hasMakerNote ? "YES" : "NO").append("\n");

                if (!hasMakerNote && make != null && !make.equalsIgnoreCase("Unknown") && make.trim().length() > 0) {
                    // just report, don't add to suspicion list or risk
                    report.append("MakerNote Note: Missing — may be lost during USB/ZIP transfer\n");
                }

                // ======================================================
                // CHECK 4: FILE CREATION DATE vs CAPTURE DATE
                // File created BEFORE capture = impossible = tampered
                // File modified AFTER capture = re-saved after editing
                // ======================================================// File creation/modified date not checked — always shows upload time, not original
                report.append("File Creation Date: Not checked (shows server upload time only)\n");

                // ======================================================
                // CHECK 5: GPS vs TIMEZONE OFFSET CONSISTENCY
                // If photo says +05:30 (India) but GPS shows USA — suspicious
                // ======================================================
                double lat = 0, lon = 0;
                boolean hasGPS = false;
                String location = "Unknown Location";

                if (gps != null) {
                    GeoLocation g = gps.getGeoLocation();
                    if (g != null && !g.isZero()) {
                        hasGPS = true;
                        lat = g.getLatitude();
                        lon = g.getLongitude();
                        location = reverseGeocode(lat, lon);

                        report.append("Latitude: ").append(lat).append("\n");
                        report.append("Longitude: ").append(lon).append("\n");

                        if (offsetTimeOriginal != null && !offsetTimeOriginal.isEmpty()) {
                            int exifOffsetMins = parseOffsetMinutes(offsetTimeOriginal);
                            int expectedOffsetMins = estimateTimezoneOffset(lat, lon);
                            int diff = Math.abs(exifOffsetMins - expectedOffsetMins);

                            report.append("EXIF Timezone Offset: ").append(offsetTimeOriginal).append("\n");
                            report.append("Expected Timezone (from GPS): UTC")
                                    .append(expectedOffsetMins >= 0 ? "+" : "")
                                    .append(expectedOffsetMins / 60).append("\n");

                            if (diff > 120) {
                                risk += 30;
                                suspicions.add("GPS location timezone does not match EXIF timezone offset (diff=" + diff + " mins) — GPS or timestamp may be faked");
                            }
                        }

                    } else {
                        risk += 20;
                        suspicions.add("GPS tag present but coordinates are zero — GPS data may have been wiped");
                    }
                } else {
                    risk += 20;
                    suspicions.add("No GPS data found");
                }

                report.append("Location: ").append(location).append("\n");
                report.append("Area Classification: ").append(classifyArea(location)).append("\n");

                // ======================================================
                // CHECK 6: CAMERA MODEL vs IMAGE RESOLUTION
                // e.g. iPhone 6 claiming 50MP is suspicious
                // ======================================================
                String dimStr = getDimensions(metadata);
                report.append("Dimensions: ").append(dimStr).append("\n");

                if (model != null && !model.equalsIgnoreCase("Unknown") && !dimStr.equals("Not Available")) {
                    String modelLower = model.toLowerCase();
                    int[] dims = parseDimensions(dimStr);
                    if (dims != null) {
                        long megapixels = ((long) dims[0] * dims[1]) / 1_000_000;
                        report.append("Megapixels (approx): ").append(megapixels).append(" MP\n");

                        boolean suspicious = false;
                        if (modelLower.contains("iphone 6") && megapixels > 20) suspicious = true;
                        if (modelLower.contains("iphone 7") && megapixels > 20) suspicious = true;
                        if (modelLower.contains("iphone 8") && megapixels > 20) suspicious = true;
                        if (modelLower.contains("iphone x") && megapixels > 20) suspicious = true;
                        if (modelLower.contains("iphone 11") && megapixels > 20) suspicious = true;
                        if (modelLower.contains("iphone 12") && megapixels > 25) suspicious = true;
                        if (modelLower.contains("iphone 13") && megapixels > 25) suspicious = true;
                        if (modelLower.contains("iphone 14") && megapixels > 25) suspicious = true;
                        if ((modelLower.contains("iphone") || modelLower.contains("samsung") ||
                                modelLower.contains("pixel")) && megapixels < 2) suspicious = true;

                        if (suspicious) {
                            risk += 20;
                            suspicions.add("Image resolution (" + megapixels + " MP) is inconsistent with camera model (" + model + ") — model name may be faked");
                        }
                    }
                }

                // ======================================================
                // AUTHENTICITY SCORE
                // ======================================================
                int authenticity = Math.max(0, 100 - risk);
                report.append("Risk Score: ").append(risk).append("\n");
                report.append("Authenticity Score: ").append(authenticity).append("\n");
                report.append(authenticity < 40 ? "Status: HIGHLY SUSPICIOUS\n" :
                        authenticity < 70 ? "Status: Possibly Modified\n" :
                                "Status: Likely Genuine\n");

                // ======================================================
                // TAMPERING SUSPICION SUMMARY
                // ======================================================
                report.append("\n----- TAMPERING SUSPICION ANALYSIS -----\n");
                if (suspicions.isEmpty()) {
                    report.append("No tampering indicators found.\n");
                } else {
                    report.append("Total Suspicion Indicators: ").append(suspicions.size()).append("\n");
                    for (int i = 0; i < suspicions.size(); i++) {
                        report.append("[").append(i + 1).append("] ").append(suspicions.get(i)).append("\n");
                    }
                }
                report.append("\n----- POSSIBLY MODIFIED FIELDS -----\n");

                if (software != null) {
                    String sw = software.toLowerCase();
                    if (sw.contains("photoshop") || sw.contains("exiftool") ||
                            sw.contains("gimp") || sw.contains("lightroom")) {
                        report.append("- date_time_original    : Possibly Modified\n");
                        report.append("- create_date           : Possibly Modified\n");
                        report.append("- modify_date           : Possibly Modified\n");
                        report.append("- make                  : Possibly Fake\n");
                        report.append("- model                 : Possibly Fake\n");
                        report.append("- software              : Rewritten by " + software + "\n");
                        report.append("- image_description     : Possibly Modified\n");
                    }
                }

                if (!hasMakerNote && make != null && !make.equalsIgnoreCase("Unknown")) {
                    report.append("- make/model            : Possibly Fake (MakerNote absent)\n");
                }

                if (thumbDir == null || thumbDir.getString(ExifThumbnailDirectory.TAG_DATETIME) == null) {
                    report.append("- date_time_original    : Possibly Modified (Thumbnail date removed)\n");
                    report.append("- create_date           : Possibly Modified\n");
                }

                if (hasGPS) {
                    if (offsetTimeOriginal != null) {
                        int exifOffsetMins = parseOffsetMinutes(offsetTimeOriginal);
                        int expectedOffsetMins = estimateTimezoneOffset(lat, lon);
                        int diff = Math.abs(exifOffsetMins - expectedOffsetMins);
                        if (diff > 120) {
                            report.append("- gps_latitude          : Possibly Fake\n");
                            report.append("- gps_date_stamp        : Possibly Modified\n");
                            report.append("- gps_time_stamp        : Possibly Modified\n");
                            report.append("- gps_altitude          : Possibly Modified\n");
                        }
                    }
                }

                if (suspicions.size() >= 3) {
                    report.append("- sub_sec_date_time_original : Possibly Modified\n");
                    report.append("- sub_sec_create_date        : Possibly Modified\n");
                    report.append("- sub_sec_modify_date        : Possibly Modified\n");
                }
                report.append("\n----- FORENSIC SUMMARY -----\n");
                report.append("File Size: ").append(saved.length() / 1024).append(" KB\n");
                report.append("GPS Present: ").append(hasGPS ? "YES" : "NO").append("\n");

                if (hasGPS && captureDate != null)
                    movement.add(new ImageData(captureDate, lat, lon));

            } catch (Exception e) {
                e.printStackTrace();
                report.append("Error processing file\n");
            }
        }

        if (movement.size() >= 2)
            report.append(generateMovement(movement));

        lastFullReport = report.toString();
        lastCourtReport = "DIGITAL COURT ADMISSIBLE FORENSIC REPORT\n\n" + lastFullReport;

        return lastFullReport;
    }

    // ================= TIMESTAMP HELPERS =================

    private TimeZone parseTimezone(String offset) {
        try {
            if (offset == null || offset.trim().isEmpty()) return TimeZone.getDefault();
            offset = offset.trim();
            if (offset.equalsIgnoreCase("Z")) return TimeZone.getTimeZone("UTC");
            return TimeZone.getTimeZone("GMT" + offset);
        } catch (Exception e) {
            return TimeZone.getDefault();
        }
    }

    private Date parseExifDateTime(String raw) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy:MM:dd HH:mm:ss");
            sdf.setTimeZone(TimeZone.getDefault());
            return sdf.parse(raw);
        } catch (Exception e) {
            return null;
        }
    }

    private String formatDateLocal(String raw) {
        try {
            SimpleDateFormat inFmt = new SimpleDateFormat("yyyy:MM:dd HH:mm:ss");
            inFmt.setTimeZone(TimeZone.getDefault());
            Date d = inFmt.parse(raw);
            SimpleDateFormat outFmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss a");
            outFmt.setTimeZone(TimeZone.getDefault());
            return outFmt.format(d);
        } catch (Exception e) {
            return raw;
        }
    }

    // ================= NEW HELPERS =================

    private int parseOffsetMinutes(String offset) {
        try {
            offset = offset.trim();
            int sign = offset.startsWith("-") ? -1 : 1;
            offset = offset.replace("+", "").replace("-", "");
            String[] parts = offset.split(":");
            int hours = Integer.parseInt(parts[0]);
            int mins = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
            return sign * (hours * 60 + mins);
        } catch (Exception e) {
            return 0;
        }
    }

    // Rough UTC offset from longitude (15 degrees = 1 hour)
    private int estimateTimezoneOffset(double lat, double lon) {
        try {
            return (int) (lon / 15.0) * 60;
        } catch (Exception e) {
            return Integer.MIN_VALUE;
        }
    }

    private int[] parseDimensions(String dimStr) {
        try {
            dimStr = dimStr.trim();
            if (dimStr.contains("x")) {
                String[] parts = dimStr.split("x");
                int w = Integer.parseInt(parts[0].replaceAll("[^0-9]", "").trim());
                int h = Integer.parseInt(parts[1].replaceAll("[^0-9]", "").trim());
                return new int[]{w, h};
            } else {
                int w = Integer.parseInt(dimStr.replaceAll("[^0-9]", "").trim());
                return new int[]{w, w};
            }
        } catch (Exception e) {
            return null;
        }
    }

    // ================= MOVEMENT =================

    private String generateMovement(List<ImageData> list) {

        list.sort(Comparator.comparing((ImageData i) -> i.date));

        ImageData a = list.get(0);
        ImageData b = list.get(list.size() - 1);

        double hours = Math.abs(b.date.getTime() - a.date.getTime()) / 3600000.0;
        double days = hours / 24.0;

        double air = haversine(a.lat, a.lon, b.lat, b.lon);
        double road = getRoadDistance(a.lat, a.lon, b.lat, b.lon);
        double speed = road / Math.max(hours, 1);

        StringBuilder r = new StringBuilder("\n=========== MOVEMENT FORENSIC REPORT ===========\n");

        r.append("FROM: ").append(a.date).append("\n");
        r.append("TO: ").append(b.date).append("\n");
        r.append("Time Gap: ").append(round(hours)).append(" hrs (").append(round(days)).append(" days)\n\n");
        r.append("AIR DISTANCE: ").append(round(air)).append(" km\n");
        r.append("ROAD DISTANCE: ").append(round(road)).append(" km\n");
        r.append("AVG SPEED: ").append(round(speed)).append(" km/h\n");
        r.append("MOVEMENT TYPE: ").append(classifyMovement(speed)).append("\n");

        return r.toString();
    }

    private double getRoadDistance(double lat1, double lon1, double lat2, double lon2) {
        try {
            String url = "https://api.openrouteservice.org/v2/directions/driving-car?api_key=" + ORS_KEY +
                    "&start=" + lon1 + "," + lat1 + "&end=" + lon2 + "," + lat2;

            Map<?, ?> json = new ObjectMapper().readValue(new URL(url), Map.class);
            Map<?, ?> feature = (Map<?, ?>) ((List<?>) json.get("features")).get(0);
            Map<?, ?> summary = (Map<?, ?>) ((Map<?, ?>) feature.get("properties")).get("summary");

            return ((Number) summary.get("distance")).doubleValue() / 1000.0;

        } catch (Exception e) {
            return 0;
        }
    }

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

        if (type.equals("court")) {

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

            for (String line : lastFullReport.split("\n")) {
                if (line.contains("File:") ||
                        line.contains("SHA256:") ||
                        line.contains("Capture Time:") ||
                        line.contains("Location:") ||
                        line.contains("Area Classification:") ||
                        line.contains("Risk Score:") ||
                        line.contains("Authenticity Score:") ||
                        line.contains("Status:") ||
                        line.contains("Software Tag:") ||
                        line.contains("MakerNote Present:") ||
                        line.contains("Thumbnail DateTime:") ||
                        line.contains("Thumbnail Date Match:") ||
                        line.contains("File Creation Date:") ||
                        line.contains("File Modified Date:") ||
                        line.contains("Megapixels") ||
                        line.contains("EXIF Timezone") ||
                        line.contains("Expected Timezone") ||
                        line.contains("Total Suspicion") ||
                        line.startsWith("[") ||
                        line.contains("No tampering indicators") ||
                        line.contains("AIR DISTANCE:") ||
                        line.contains("ROAD DISTANCE:") ||
                        line.contains("AVG SPEED:") ||
                        line.contains("MOVEMENT TYPE:") ||
                        line.contains("Time Gap:") ||
                        line.contains("TAMPERING SUSPICION"))
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

            document.add(new Paragraph("FULL DIGITAL FORENSIC METADATA REPORT"));
            document.add(new Paragraph("------------------------------------------------------------"));
            document.add(new Paragraph("Generated On: " + new Date()));
            document.add(new Paragraph("\n"));

            for (String line : lastFullReport.split("\n")) {
                document.add(new Paragraph(line));
            }
        }

        document.close();
        response.getOutputStream().write(baos.toByteArray());
        response.getOutputStream().flush();
    }

    // ================= HELPERS =================

    private String reverseGeocode(double lat, double lon) {
        try {
            String url = "https://api.opencagedata.com/geocode/v1/json?q=" +
                    URLEncoder.encode(lat + "," + lon, "UTF-8") + "&key=" + OPENCAGE_KEY;
            Map<?, ?> json = new ObjectMapper().readValue(new URL(url), Map.class);
            List<?> res = (List<?>) json.get("results");
            if (!res.isEmpty()) return ((Map<?, ?>) res.get(0)).get("formatted").toString();
        } catch (Exception ignored) {
        }
        return "Unknown Location";
    }

    private String classifyMovement(double speed) {
        if (speed > 900) return "Impossible Movement (Metadata Tampered)";
        if (speed > 300) return "Flight Travel";
        if (speed > 120) return "Vehicle Travel";
        if (speed > 15) return "Human Movement";
        return "Natural Movement";
    }

    private String classifyArea(String loc) {
        if (loc == null) return "Unknown";
        String t = loc.toLowerCase();
        if (t.contains("college") || t.contains("school")) return "Educational Institution";
        if (t.contains("hospital")) return "Medical Facility";
        if (t.contains("police") || t.contains("court")) return "Restricted Area";
        if (t.contains("mall") || t.contains("market")) return "Commercial Area";
        if (t.contains("colony") || t.contains("residential")) return "Residential Area";
        if (t.contains("park") || t.contains("lake") || t.contains("beach")) return "Public Area";
        return "General Area";
    }

    private String sha256(File f) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(f);
        byte[] b = new byte[1024];
        int n;
        while ((n = fis.read(b)) > 0) d.update(b, 0, n);
        fis.close();
        StringBuilder s = new StringBuilder();
        for (byte bb : d.digest()) s.append(String.format("%02x", bb));
        return s.toString();
    }

    private double haversine(double la1, double lo1, double la2, double lo2) {
        final int R = 6371;
        double dLat = Math.toRadians(la2 - la1), dLon = Math.toRadians(lo2 - lo1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(la1)) * Math.cos(Math.toRadians(la2)) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }

    private double round(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    private String getDimensions(Metadata metadata) {
        try {
            String width = null, height = null;
            for (Directory d : metadata.getDirectories()) {
                for (Tag t : d.getTags()) {
                    if (t.getTagName().equalsIgnoreCase("Image Width")) width = t.getDescription();
                    if (t.getTagName().equalsIgnoreCase("Image Height")) height = t.getDescription();
                }
            }
            if (width != null && height != null) return width + " x " + height;
            if (width != null) return width;
        } catch (Exception ignored) {
        }
        return "Not Available";
    }

    private String safe(String value) {
        return value == null ? "Not Provided" : value;
    }

    static class ImageData {
        Date date;
        double lat, lon;

        ImageData(Date d, double la, double lo) {
            date = d;
            lat = la;
            lon = lo;
        }
    }
}