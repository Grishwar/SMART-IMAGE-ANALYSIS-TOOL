package com.example.metaextract;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import jakarta.servlet.http.HttpServletResponse;

import javax.imageio.ImageIO;
import javax.imageio.IIOImage;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.MemoryCacheImageOutputStream;

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
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

@RestController
public class FileUploadController {

    private static final String UPLOAD_DIR =
            System.getProperty("user.home") +
                    File.separator + "metaextract_uploads";



    // ── Train RF + SVM on VISION dataset at startup ──
    private static ForensicRandomForest randomForest;
    private static ForensicSVM svmModel;

    static {
        try {
            String csvPath =
                    "C:/Users/rajhe/OneDrive/Desktop/" +
                            "VISION DATASET/dataset.csv";

            List<double[]> allData = new ArrayList<>();
            java.io.BufferedReader br =
                    new java.io.BufferedReader(
                            new java.io.FileReader(csvPath)
                    );
            String line;
            boolean header = true;
            while ((line = br.readLine()) != null) {
                if (header) {
                    header = false;
                    continue;
                }
                String[] p = line.split(",");
                if (p.length < 9) continue;
                double[] row = new double[8];
                for (int i = 0; i < 8; i++) {
                    row[i] = Double.parseDouble(
                            p[i + 1].trim()
                    );
                }
                allData.add(row);
            }
            br.close();

            Collections.shuffle(
                    allData, new Random(42)
            );
            int trainSize =
                    (int)(allData.size() * 0.8);
            double[][] trainData =
                    allData.subList(0, trainSize)
                            .toArray(new double[0][]);

            randomForest =
                    new ForensicRandomForest(trainData);
            svmModel = new ForensicSVM(trainData);

            System.out.println(
                    "✅ RF + SVM trained on " +
                            trainSize +
                            " real VISION images!"
            );

        } catch (Exception e) {
            System.out.println(
                    "⚠️ dataset.csv not found! " +
                            "Using default models. " +
                            "Run FeatureExtractor first!"
            );
            randomForest = new ForensicRandomForest();
            svmModel = new ForensicSVM();
        }
    }

    private String lastFullReport = "";
    private Map<String, String> aiSummaryStore =
            new HashMap<>();
    private List<ForensicKMeans.ImagePoint>
            clusterPoints = new ArrayList<>();

    // ========================= ANALYZE =========================
    @PostMapping("/analyze")
    public String analyze(
            @RequestParam("files") MultipartFile[] files
    ) {
        StringBuilder report = new StringBuilder();
        report.append(
                "\n=========== FORENSIC IMAGE REPORT ===========\n"
        );

        File dir = new File(UPLOAD_DIR);
        if (!dir.exists()) dir.mkdirs();

        List<ImageData> movement = new ArrayList<>();
        Set<String> hashes = new HashSet<>();
        aiSummaryStore.clear();
        clusterPoints.clear();

        for (MultipartFile file : files) {
            try {
                if (file.isEmpty()) continue;

                String name = System.currentTimeMillis()
                        + "_" + file.getOriginalFilename();
                File saved = new File(dir, name);
                file.transferTo(saved);

                report.append(
                        "\n============================================\n"
                );
                report.append("File: ")
                        .append(name).append("\n");

                String hash = sha256(saved);
                if (hashes.contains(hash)) {
                    report.append("Duplicate: YES\n");
                } else {
                    hashes.add(hash);
                    report.append("Duplicate: NO\n");
                }
                report.append("SHA256: ")
                        .append(hash).append("\n");

                Metadata metadata =
                        ImageMetadataReader.readMetadata(saved);

                ExifSubIFDDirectory dateDir =
                        metadata.getFirstDirectoryOfType(
                                ExifSubIFDDirectory.class);
                ExifIFD0Directory camDir =
                        metadata.getFirstDirectoryOfType(
                                ExifIFD0Directory.class);
                GpsDirectory gps =
                        metadata.getFirstDirectoryOfType(
                                GpsDirectory.class);
                ExifThumbnailDirectory thumbDir =
                        metadata.getFirstDirectoryOfType(
                                ExifThumbnailDirectory.class);

                int risk = 0;
                List<String> suspicions =
                        new ArrayList<>();
                Date captureDate = null;
                String captureDateStr = "Not Available";

                String offsetTimeOriginal = null;
                if (dateDir != null) {
                    offsetTimeOriginal =
                            dateDir.getString(0x9011);
                    if (offsetTimeOriginal == null)
                        offsetTimeOriginal =
                                dateDir.getString(0x9010);
                }

                if (dateDir != null) {
                    if (offsetTimeOriginal != null &&
                            !offsetTimeOriginal.isEmpty()) {
                        TimeZone tz = parseTimezone(
                                offsetTimeOriginal);
                        captureDate =
                                dateDir.getDateOriginal(tz);
                    } else {
                        String rawDateTime =
                                dateDir.getString(
                                        ExifSubIFDDirectory
                                                .TAG_DATETIME_ORIGINAL);
                        if (rawDateTime != null &&
                                !rawDateTime.isEmpty()) {
                            captureDate =
                                    parseExifDateTime(rawDateTime);
                            captureDateStr =
                                    formatDateLocal(rawDateTime);
                        }
                    }
                    if (captureDate != null &&
                            captureDateStr.equals(
                                    "Not Available")) {
                        SimpleDateFormat sdf =
                                new SimpleDateFormat(
                                        "yyyy-MM-dd hh:mm:ss a");
                        if (offsetTimeOriginal != null) {
                            sdf.setTimeZone(parseTimezone(
                                    offsetTimeOriginal));
                            captureDateStr =
                                    sdf.format(captureDate) +
                                            " " + offsetTimeOriginal;
                        } else {
                            sdf.setTimeZone(
                                    TimeZone.getDefault());
                            captureDateStr =
                                    sdf.format(captureDate) +
                                            " (device local time)";
                        }
                    }
                }

                if (captureDate == null &&
                        camDir != null) {
                    String rawDateTime =
                            camDir.getString(
                                    ExifIFD0Directory.TAG_DATETIME);
                    if (rawDateTime != null &&
                            !rawDateTime.isEmpty()) {
                        captureDate =
                                parseExifDateTime(rawDateTime);
                        captureDateStr =
                                formatDateLocal(rawDateTime) +
                                        " (file modification time)";
                    }
                }

                if (captureDate != null) {
                    report.append("Capture Time: ")
                            .append(captureDateStr)
                            .append("\n");
                } else {
                    report.append(
                            "Capture Time: Not Available\n");
                    risk += 30;
                    suspicions.add(
                            "Capture timestamp missing " +
                                    "— possible metadata wipe");
                }

                String make = camDir != null ?
                        camDir.getString(
                                ExifIFD0Directory.TAG_MAKE) :
                        "Unknown";
                String model = camDir != null ?
                        camDir.getString(
                                ExifIFD0Directory.TAG_MODEL) :
                        "Unknown";
                report.append("Camera: ")
                        .append(make).append(" ")
                        .append(model).append("\n");

                String software = camDir != null ?
                        camDir.getString(
                                ExifIFD0Directory.TAG_SOFTWARE) :
                        null;
                report.append("Software Tag: ")
                        .append(software != null ?
                                software : "Not Present")
                        .append("\n");

                if (software != null) {
                    String sw = software.toLowerCase();
                    boolean isGenuine =
                            sw.contains("mediatek") ||
                                    sw.contains("camera application") ||
                                    sw.contains("camera2") ||
                                    sw.contains("gcam") ||
                                    sw.contains("miui") ||
                                    sw.contains("samsung camera") ||
                                    sw.contains("pixel camera") ||
                                    sw.contains("iphone") ||
                                    sw.contains("apple");
                    if (isGenuine) {
                        report.append("Software Note: ")
                                .append(software)
                                .append(" (Genuine camera app)\n");
                    } else if (sw.contains("exiftool")) {
                        risk += 40;
                        suspicions.add(
                                "ExifTool detected — " +
                                        "metadata edited");
                    } else if (sw.contains("photoshop")) {
                        risk += 40;
                        suspicions.add(
                                "Adobe Photoshop detected — " +
                                        "image may be edited");
                    } else if (sw.contains("gimp")) {
                        risk += 35;
                        suspicions.add(
                                "GIMP detected — " +
                                        "image may be edited");
                    } else if (sw.contains("lightroom")) {
                        risk += 30;
                        suspicions.add(
                                "Adobe Lightroom detected — " +
                                        "image was post-processed");
                    } else if (sw.contains("paint") ||
                            sw.contains("snapseed") ||
                            sw.contains("pixlr")) {
                        risk += 25;
                        suspicions.add(
                                "Photo editing app detected: " +
                                        software);
                    }
                } else {
                    risk += 5;
                    report.append(
                            "Software Note: Not present\n");
                }

                if (thumbDir != null && dateDir != null) {
                    String thumbDateTime =
                            thumbDir.getString(
                                    ExifThumbnailDirectory
                                            .TAG_DATETIME);
                    String origDateTime =
                            dateDir.getString(
                                    ExifSubIFDDirectory
                                            .TAG_DATETIME_ORIGINAL);
                    report.append("Thumbnail DateTime: ")
                            .append(thumbDateTime != null ?
                                    thumbDateTime : "Not Present")
                            .append("\n");
                    if (thumbDateTime != null &&
                            origDateTime != null) {
                        if (!thumbDateTime.trim().equals(
                                origDateTime.trim())) {
                            risk += 35;
                            suspicions.add(
                                    "THUMBNAIL DATE MISMATCH — " +
                                            "strong sign of tampering");
                        } else {
                            report.append(
                                    "Thumbnail Date Match: " +
                                            "YES (consistent)\n");
                        }
                    }
                } else {
                    report.append(
                            "Thumbnail DateTime: Not Available\n");
                }

                boolean hasMakerNote = false;
                for (Directory d :
                        metadata.getDirectories()) {
                    String dirName =
                            d.getName().toLowerCase();
                    if (dirName.contains("makernote")) {
                        hasMakerNote = true;
                        break;
                    }
                }
                report.append("MakerNote Present: ")
                        .append(hasMakerNote ? "YES" : "NO")
                        .append("\n");

                report.append(
                        "File Creation Date: Not checked\n");

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
                        report.append("Latitude: ")
                                .append(lat).append("\n");
                        report.append("Longitude: ")
                                .append(lon).append("\n");
                        if (offsetTimeOriginal != null &&
                                !offsetTimeOriginal.isEmpty()) {
                            int exifOff =
                                    parseOffsetMinutes(
                                            offsetTimeOriginal);
                            int expOff =
                                    estimateTimezoneOffset(
                                            lat, lon);
                            int diff = Math.abs(
                                    exifOff - expOff);
                            report.append(
                                            "EXIF Timezone Offset: ")
                                    .append(offsetTimeOriginal)
                                    .append("\n");
                            report.append(
                                            "Expected Timezone (GPS): UTC")
                                    .append(expOff >= 0 ?
                                            "+" : "")
                                    .append(expOff / 60)
                                    .append("\n");
                            if (diff > 120) {
                                risk += 30;
                                suspicions.add(
                                        "Timezone mismatch — " +
                                                "GPS or timestamp faked");
                            }
                        }
                    } else {
                        risk += 20;
                        suspicions.add(
                                "GPS zero coordinates — " +
                                        "data may be wiped");
                    }
                } else {
                    risk += 20;
                    suspicions.add("No GPS data found");
                }

                report.append("Location: ")
                        .append(location).append("\n");
                report.append("Area Classification: ")
                        .append(classifyArea(location))
                        .append("\n");

                String dimStr = getDimensions(metadata);
                report.append("Dimensions: ")
                        .append(dimStr).append("\n");

                if (model != null &&
                        !model.equalsIgnoreCase("Unknown") &&
                        !dimStr.equals("Not Available")) {
                    String ml = model.toLowerCase();
                    int[] dims = parseDimensions(dimStr);
                    if (dims != null) {
                        long mp = ((long)dims[0]*dims[1])
                                / 1_000_000;
                        report.append(
                                        "Megapixels (approx): ")
                                .append(mp).append(" MP\n");
                        boolean susp = false;
                        if (ml.contains("iphone 6") &&
                                mp > 20) susp = true;
                        if (ml.contains("iphone 7") &&
                                mp > 20) susp = true;
                        if (ml.contains("iphone 8") &&
                                mp > 20) susp = true;
                        if ((ml.contains("iphone") ||
                                ml.contains("samsung") ||
                                ml.contains("pixel")) &&
                                mp < 2) susp = true;
                        if (susp) {
                            risk += 20;
                            suspicions.add(
                                    "Resolution inconsistent " +
                                            "with model: " + model);
                        }
                    }
                }

                String elaResult = "Not Available";
                try {
                    elaResult = performELA(saved);
                    report.append("ELA Result: ")
                            .append(elaResult).append("\n");
                    String elaBase64 =
                            generateELAImageBase64(saved);
                    if (elaBase64 != null) {
                        report.append("ELA_IMAGE_BASE64: ")
                                .append(elaBase64).append("\n");
                        if (elaResult.contains("HIGH")) {
                            risk += 30;
                            suspicions.add(
                                    "ELA HIGH pixel " +
                                            "inconsistency detected");
                        } else if (
                                elaResult.contains("MEDIUM")) {
                            risk += 15;
                            suspicions.add(
                                    "ELA MEDIUM pixel " +
                                            "inconsistency detected");
                        }
                    }
                } catch (Exception e) {
                    report.append(
                            "ELA Result: Not Available\n");
                }

                int authenticity =
                        Math.max(0, 100 - risk);
                report.append("Risk Score: ")
                        .append(risk).append("\n");
                report.append("Authenticity Score: ")
                        .append(authenticity).append("\n");
                String statusStr =
                        authenticity < 40 ?
                                "HIGHLY SUSPICIOUS" :
                                authenticity < 70 ?
                                        "Possibly Modified" :
                                        "Likely Genuine";
                report.append("Status: ")
                        .append(statusStr).append("\n");

                // ── Build feature vector ──
                double f0 = 0;
                if (software != null) {
                    String sw = software.toLowerCase();
                    boolean isGen =
                            sw.contains("mediatek") ||
                                    sw.contains("camera") ||
                                    sw.contains("apple") ||
                                    sw.contains("miui");
                    boolean isTamp =
                            sw.contains("photoshop") ||
                                    sw.contains("exiftool") ||
                                    sw.contains("gimp") ||
                                    sw.contains("lightroom");
                    f0 = isTamp ? 2 : (isGen ? 1 : 0);
                }
                double f1 = 0;
                if (thumbDir != null && dateDir != null) {
                    String td = thumbDir.getString(
                            ExifThumbnailDirectory.TAG_DATETIME);
                    String od = dateDir.getString(
                            ExifSubIFDDirectory
                                    .TAG_DATETIME_ORIGINAL);
                    if (td != null && od != null &&
                            !td.trim().equals(od.trim()))
                        f1 = 1;
                }
                double f2 = 0;
                double f3 = hasGPS ? 0 : 1;
                double f4 = 0;
                if (offsetTimeOriginal != null && hasGPS) {
                    int eo = parseOffsetMinutes(
                            offsetTimeOriginal);
                    int ep = estimateTimezoneOffset(
                            lat, lon);
                    if (Math.abs(eo - ep) > 120) f4 = 1;
                }
                double f5 = suspicions.stream()
                        .anyMatch(s ->
                                s.contains("resolution")) ? 1 : 0;
                double f6 =
                        elaResult.contains("HIGH") ? 2 :
                                elaResult.contains("MEDIUM") ? 1 : 0;

                double[] rfFeatures =
                        {f0, f1, f2, f3, f4, f5, f6};

                // ── RF Prediction ──
                ForensicRandomForest.ForensicResult rfResult =
                        randomForest.predict(rfFeatures);
                report.append(
                        "\n----- RANDOM FOREST ML PREDICTION -----\n");
                report.append("RF Verdict: ")
                        .append(rfResult.verdict).append("\n");
                report.append("RF Tampered Confidence: ")
                        .append(rfResult.tamperedConfidence)
                        .append("%\n");
                report.append("RF Genuine Confidence: ")
                        .append(rfResult.genuineConfidence)
                        .append("%\n");
                if (!rfResult.featureImportance.isEmpty()) {
                    report.append("Feature Contributions:\n")
                            .append(rfResult.featureImportance)
                            .append("\n");
                }

                // ── SVM Prediction ──
                ForensicSVM.SVMResult svmResult =
                        svmModel.predict(rfFeatures);
                report.append(
                        "\n----- SVM PREDICTION -----\n");
                report.append("SVM Verdict: ")
                        .append(svmResult.verdict)
                        .append("\n");
                report.append("SVM Tampered Confidence: ")
                        .append(svmResult.tamperedConfidence)
                        .append("%\n");
                report.append("SVM Genuine Confidence: ")
                        .append(svmResult.genuineConfidence)
                        .append("%\n");

                // ── KMeans point ──
                if (hasGPS && captureDate != null) {
                    double captureHour = 0;
                    try {
                        java.util.Calendar cal =
                                java.util.Calendar.getInstance();
                        cal.setTime(captureDate);
                        captureHour = cal.get(
                                java.util.Calendar.HOUR_OF_DAY);
                    } catch (Exception ignored) {}
                    clusterPoints.add(
                            new ForensicKMeans.ImagePoint(
                                    name, lat, lon, risk,
                                    captureHour));
                }

                report.append(
                        "\n----- TAMPERING SUSPICION ANALYSIS -----\n");
                if (suspicions.isEmpty()) {
                    report.append(
                            "No tampering indicators found.\n");
                } else {
                    report.append(
                                    "Total Suspicion Indicators: ")
                            .append(suspicions.size())
                            .append("\n");
                    for (int i = 0;
                         i < suspicions.size(); i++) {
                        report.append("[").append(i + 1)
                                .append("] ")
                                .append(suspicions.get(i))
                                .append("\n");
                    }
                }

                report.append(
                        "\n----- POSSIBLY MODIFIED FIELDS -----\n");
                boolean anyModified = false;
                if (software != null) {
                    String sw = software.toLowerCase();
                    if (sw.contains("photoshop") ||
                            sw.contains("exiftool") ||
                            sw.contains("gimp") ||
                            sw.contains("lightroom")) {
                        report.append(
                                "- Image Content: " +
                                        "Possibly Modified\n");
                        report.append(
                                "- Capture Date/Time: " +
                                        "Possibly Modified\n");
                        report.append(
                                "- Software Tag: Rewritten by " +
                                        software + "\n");
                        anyModified = true;
                    }
                }
                if (!hasMakerNote && make != null &&
                        !make.equalsIgnoreCase("Unknown")) {
                    report.append(
                            "- Camera Make/Model: " +
                                    "Possibly Fake (MakerNote absent)\n");
                    anyModified = true;
                }
                if (!anyModified) {
                    report.append(
                            "No specific fields modified.\n");
                }

                String forensicData =
                        buildForensicDataForAI(
                                file.getOriginalFilename(),
                                captureDateStr, make, model,
                                software, location, hasGPS,
                                lat, lon, risk, authenticity,
                                statusStr, suspicions, elaResult);
                String aiSummary =
                        generateAISummary(forensicData);
                report.append(
                        "\n----- AI FORENSIC SUMMARY -----\n");
                report.append(aiSummary).append("\n");
                aiSummaryStore.put(name, aiSummary);

                report.append(
                        "\n----- FORENSIC SUMMARY -----\n");
                report.append("File Size: ")
                        .append(saved.length() / 1024)
                        .append(" KB\n");
                report.append("GPS Present: ")
                        .append(hasGPS ? "YES" : "NO")
                        .append("\n");

                if (hasGPS && captureDate != null)
                    movement.add(new ImageData(
                            captureDate, lat, lon));

            } catch (Exception e) {
                e.printStackTrace();
                report.append("Error processing file\n");
            }
        }

        if (movement.size() >= 2)
            report.append(generateMovement(movement));

        if (clusterPoints.size() >= 2) {
            List<ForensicKMeans.ClusterResult> clusters =
                    ForensicKMeans.cluster(clusterPoints);
            report.append(
                    ForensicKMeans.formatResults(clusters));
        }

        lastFullReport = report.toString();
        return lastFullReport;
    }

    @PostMapping("/aiSummary")
    public String getAiSummary(
            @RequestParam("fileName") String fileName
    ) {
        String summary = aiSummaryStore.get(fileName);
        if (summary != null && !summary.isEmpty())
            return summary;
        return "AI Summary not available.";
    }

    private String buildForensicDataForAI(
            String fileName, String captureTime,
            String make, String model, String software,
            String location, boolean hasGPS,
            double lat, double lon,
            int risk, int authenticity, String status,
            List<String> suspicions, String elaResult
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(fileName).append("\n");
        sb.append("Capture Time: ").append(captureTime)
                .append("\n");
        sb.append("Camera: ").append(make).append(" ")
                .append(model).append("\n");
        sb.append("Software Tag: ")
                .append(software != null ? software :
                        "Not Present").append("\n");
        sb.append("Location: ").append(location)
                .append("\n");
        sb.append("GPS: ").append(hasGPS ?
                        "YES (" + lat + "," + lon + ")" : "NO")
                .append("\n");
        sb.append("Risk Score: ").append(risk).append("\n");
        sb.append("Authenticity: ").append(authenticity)
                .append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("ELA: ").append(elaResult).append("\n");
        sb.append("Indicators: ")
                .append(suspicions.size()).append("\n");
        for (String s : suspicions)
            sb.append("  - ").append(s).append("\n");
        return sb.toString();
    }

    private String generateAISummary(
            String forensicData
    ) {
        try {
            String prompt =
                    "You are a digital forensic expert.\n" +
                            "Write a plain English summary (5-7 sentences):\n" +
                            "1. When and where photo was taken\n" +
                            "2. What device was used\n" +
                            "3. Is image tampered or genuine\n" +
                            "4. What may be modified\n" +
                            "5. Final verdict for court\n\n" +
                            "FORENSIC DATA:\n" + forensicData;

            String requestBody = "{"
                    + "\"model\":\"llama-3.3-70b-versatile\","
                    + "\"messages\":[{\"role\":\"user\","
                    + "\"content\":" + toJson(prompt) + "}],"
                    + "\"max_tokens\":500,"
                    + "\"temperature\":0.3"
                    + "}";

            URL url = new URL(
                    "https://api.groq.com/openai/v1/" +
                            "chat/completions");
            HttpURLConnection conn =
                    (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty(
                    "Content-Type", "application/json");
            conn.setRequestProperty(
                    "Authorization", "Bearer " + GROQ_API_KEY);
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);

            OutputStream os = conn.getOutputStream();
            os.write(requestBody.getBytes(
                    StandardCharsets.UTF_8));
            os.flush();
            os.close();

            int code = conn.getResponseCode();
            InputStream is = code == 200 ?
                    conn.getInputStream() :
                    conn.getErrorStream();
            String response = new String(
                    is.readAllBytes(),
                    StandardCharsets.UTF_8);
            is.close();

            if (code == 200) {
                Map<?, ?> json =
                        new ObjectMapper()
                                .readValue(response, Map.class);
                List<?> choices =
                        (List<?>) json.get("choices");
                if (choices != null &&
                        !choices.isEmpty()) {
                    Map<?, ?> choice =
                            (Map<?, ?>) choices.get(0);
                    Map<?, ?> message =
                            (Map<?, ?>) choice.get("message");
                    return message.get("content")
                            .toString().trim();
                }
            }
            return "AI Summary not available — code: " +
                    code;
        } catch (Exception e) {
            return "AI Summary not available — " +
                    e.getMessage();
        }
    }

    private String toJson(String text) {
        return "\"" + text
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private String performELA(File imageFile)
            throws Exception {
        BufferedImage original = ImageIO.read(imageFile);
        if (original == null)
            return "Not Available";
        BufferedImage recompressed =
                recompressImage(original, 0.95f);
        int width = Math.min(
                original.getWidth(),
                recompressed.getWidth());
        int height = Math.min(
                original.getHeight(),
                recompressed.getHeight());
        long totalDiff = 0, highDiffPixels = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                Color c1 =
                        new Color(original.getRGB(x, y));
                Color c2 =
                        new Color(recompressed.getRGB(x, y));
                int diff =
                        Math.abs(c1.getRed()-c2.getRed()) +
                                Math.abs(c1.getGreen()-c2.getGreen()) +
                                Math.abs(c1.getBlue()-c2.getBlue());
                totalDiff += diff;
                if (diff > 15) highDiffPixels++;
            }
        }
        long totalPixels = (long) width * height;
        double avgDiff =
                (double) totalDiff / (totalPixels * 3);
        double highPct =
                (double) highDiffPixels / totalPixels * 100;
        String level =
                highPct > 8 || avgDiff > 12 ? "HIGH" :
                        highPct > 3 || avgDiff > 6  ? "MEDIUM" : "LOW";
        return level + " (Avg diff: " +
                String.format("%.2f", avgDiff) +
                ", Suspicious px: " +
                String.format("%.2f", highPct) + "%)";
    }

    private String generateELAImageBase64(File imageFile)
            throws Exception {
        BufferedImage original = ImageIO.read(imageFile);
        if (original == null) return null;
        BufferedImage recompressed =
                recompressImage(original, 0.95f);
        int width = Math.min(
                original.getWidth(),
                recompressed.getWidth());
        int height = Math.min(
                original.getHeight(),
                recompressed.getHeight());
        int dw = Math.min(width, 800);
        int dh = (int)((double)height/width*dw);
        BufferedImage ela = new BufferedImage(
                dw, dh, BufferedImage.TYPE_INT_RGB);
        double sx = (double)width/dw;
        double sy = (double)height/dh;
        for (int y = 0; y < dh; y++) {
            for (int x = 0; x < dw; x++) {
                int srcX = (int)(x*sx);
                int srcY = (int)(y*sy);
                Color c1 = new Color(
                        original.getRGB(srcX, srcY));
                Color c2 = new Color(
                        recompressed.getRGB(srcX, srcY));
                int r = Math.min(255,
                        Math.abs(c1.getRed()-c2.getRed())*20);
                int g = Math.min(255,
                        Math.abs(c1.getGreen()-
                                c2.getGreen())*20);
                int b = Math.min(255,
                        Math.abs(c1.getBlue()-c2.getBlue())*20);
                ela.setRGB(x, y,
                        new Color(r,g,b).getRGB());
            }
        }
        ByteArrayOutputStream baos =
                new ByteArrayOutputStream();
        ImageIO.write(ela, "png", baos);
        return Base64.getEncoder()
                .encodeToString(baos.toByteArray());
    }

    private BufferedImage recompressImage(
            BufferedImage original, float quality
    ) throws Exception {
        ByteArrayOutputStream baos =
                new ByteArrayOutputStream();
        ImageWriter writer =
                ImageIO.getImageWritersByFormatName("jpeg")
                        .next();
        ImageWriteParam param =
                writer.getDefaultWriteParam();
        param.setCompressionMode(
                ImageWriteParam.MODE_EXPLICIT);
        param.setCompressionQuality(quality);
        writer.setOutput(
                new MemoryCacheImageOutputStream(baos));
        BufferedImage rgb = new BufferedImage(
                original.getWidth(), original.getHeight(),
                BufferedImage.TYPE_INT_RGB);
        rgb.createGraphics().drawImage(
                original, 0, 0, Color.WHITE, null);
        writer.write(null,
                new IIOImage(rgb, null, null), param);
        writer.dispose();
        return ImageIO.read(
                new java.io.ByteArrayInputStream(
                        baos.toByteArray()));
    }

    private TimeZone parseTimezone(String offset) {
        try {
            if (offset == null ||
                    offset.trim().isEmpty())
                return TimeZone.getDefault();
            offset = offset.trim();
            if (offset.equalsIgnoreCase("Z"))
                return TimeZone.getTimeZone("UTC");
            return TimeZone.getTimeZone("GMT" + offset);
        } catch (Exception e) {
            return TimeZone.getDefault();
        }
    }

    private Date parseExifDateTime(String raw) {
        try {
            SimpleDateFormat sdf =
                    new SimpleDateFormat(
                            "yyyy:MM:dd HH:mm:ss");
            sdf.setTimeZone(TimeZone.getDefault());
            return sdf.parse(raw);
        } catch (Exception e) { return null; }
    }

    private String formatDateLocal(String raw) {
        try {
            SimpleDateFormat in =
                    new SimpleDateFormat(
                            "yyyy:MM:dd HH:mm:ss");
            in.setTimeZone(TimeZone.getDefault());
            Date d = in.parse(raw);
            SimpleDateFormat out =
                    new SimpleDateFormat(
                            "yyyy-MM-dd hh:mm:ss a");
            out.setTimeZone(TimeZone.getDefault());
            return out.format(d);
        } catch (Exception e) { return raw; }
    }

    private int parseOffsetMinutes(String offset) {
        try {
            offset = offset.trim();
            int sign =
                    offset.startsWith("-") ? -1 : 1;
            offset = offset.replace("+","")
                    .replace("-","");
            String[] parts = offset.split(":");
            int hours = Integer.parseInt(parts[0]);
            int mins = parts.length > 1 ?
                    Integer.parseInt(parts[1]) : 0;
            return sign * (hours * 60 + mins);
        } catch (Exception e) { return 0; }
    }

    private int estimateTimezoneOffset(
            double lat, double lon
    ) {
        try { return (int)(lon/15.0)*60; }
        catch (Exception e) {
            return Integer.MIN_VALUE;
        }
    }

    private int[] parseDimensions(String dimStr) {
        try {
            dimStr = dimStr.trim();
            if (dimStr.contains("x")) {
                String[] parts = dimStr.split("x");
                int w = Integer.parseInt(
                        parts[0].replaceAll(
                                "[^0-9]","").trim());
                int h = Integer.parseInt(
                        parts[1].replaceAll(
                                "[^0-9]","").trim());
                return new int[]{w, h};
            }
        } catch (Exception e) {}
        return null;
    }

    private String generateMovement(
            List<ImageData> list
    ) {
        list.sort(Comparator.comparing(
                (ImageData i) -> i.date));
        ImageData a = list.get(0);
        ImageData b = list.get(list.size()-1);
        double hours = Math.abs(
                b.date.getTime() - a.date.getTime())
                / 3600000.0;
        double days = hours / 24.0;
        double air = haversine(
                a.lat, a.lon, b.lat, b.lon);
        double road = getRoadDistance(
                a.lat, a.lon, b.lat, b.lon);
        double speed = road / Math.max(hours, 1);
        StringBuilder r = new StringBuilder(
                "\n=========== MOVEMENT FORENSIC " +
                        "REPORT ===========\n");
        r.append("FROM: ").append(a.date).append("\n");
        r.append("TO: ").append(b.date).append("\n");
        r.append("Time Gap: ").append(round(hours))
                .append(" hrs (").append(round(days))
                .append(" days)\n\n");
        r.append("AIR DISTANCE: ").append(round(air))
                .append(" km\n");
        r.append("ROAD DISTANCE: ").append(round(road))
                .append(" km\n");
        r.append("AVG SPEED: ").append(round(speed))
                .append(" km/h\n");
        r.append("MOVEMENT TYPE: ")
                .append(classifyMovement(speed)).append("\n");
        return r.toString();
    }

    private double getRoadDistance(
            double lat1, double lon1,
            double lat2, double lon2
    ) {
        try {
            String url =
                    "https://api.openrouteservice.org" +
                            "/v2/directions/driving-car?api_key=" +
                            ORS_KEY + "&start=" + lon1 + "," + lat1 +
                            "&end=" + lon2 + "," + lat2;
            Map<?,?> json = new ObjectMapper()
                    .readValue(new URL(url), Map.class);
            Map<?,?> feature = (Map<?,?>)
                    ((List<?>)json.get("features")).get(0);
            Map<?,?> summary = (Map<?,?>)
                    ((Map<?,?>)feature.get("properties"))
                            .get("summary");
            return ((Number)summary.get("distance"))
                    .doubleValue() / 1000.0;
        } catch (Exception e) { return 0; }
    }

    @PostMapping("/downloadPdf")
    public void downloadPdf(
            @RequestParam String type,
            @RequestParam(required=false) String caseNo,
            @RequestParam(required=false) String officer,
            @RequestParam(required=false) String department,
            HttpServletResponse response
    ) throws Exception {
        response.setContentType("application/pdf");
        String fileName = type.equals("court") ?
                "Court_Investigation_Report.pdf" :
                "Full_Metadata_Report.pdf";
        response.setHeader("Content-Disposition",
                "attachment; filename=" + fileName);
        ByteArrayOutputStream baos =
                new ByteArrayOutputStream();
        Document document = new Document();
        PdfWriter.getInstance(document, baos);
        document.open();
        Font titleFont = FontFactory.getFont(
                FontFactory.HELVETICA_BOLD, 14);
        Font normalFont = FontFactory.getFont(
                FontFactory.HELVETICA, 11);
        Font aiFont = FontFactory.getFont(
                FontFactory.HELVETICA, 11);
        if (type.equals("court")) {
            document.add(new Paragraph(
                    "DIGITAL FORENSIC COURT EVIDENCE REPORT",
                    titleFont));
            document.add(new Paragraph(
                    "--------------------", normalFont));
            document.add(new Paragraph(
                    "Case Number: " + safe(caseNo),
                    normalFont));
            document.add(new Paragraph(
                    "Officer: " + safe(officer),
                    normalFont));
            document.add(new Paragraph(
                    "Department: " + safe(department),
                    normalFont));
            document.add(new Paragraph(
                    "Generated: " + new Date(), normalFont));
            document.add(new Paragraph("\n"));
            if (!aiSummaryStore.isEmpty()) {
                document.add(new Paragraph(
                        "AI FORENSIC VERDICT", titleFont));
                document.add(new Paragraph(
                        "--------------------", normalFont));
                for (Map.Entry<String,String> entry :
                        aiSummaryStore.entrySet()) {
                    document.add(new Paragraph(
                            "File: " + entry.getKey(),
                            FontFactory.getFont(
                                    FontFactory.HELVETICA_BOLD,
                                    10)));
                    document.add(new Paragraph(
                            entry.getValue(), aiFont));
                    document.add(
                            new Paragraph("\n"));
                }
            }
            document.add(new Paragraph(
                    "EVIDENCE SUMMARY", titleFont));
            document.add(new Paragraph(
                    "--------------------", normalFont));
            for (String line :
                    lastFullReport.split("\n")) {
                if (line.contains("File:") ||
                        line.contains("SHA256:") ||
                        line.contains("Capture Time:") ||
                        line.contains("Location:") ||
                        line.contains("Risk Score:") ||
                        line.contains("Authenticity Score:") ||
                        line.contains("Status:") ||
                        line.contains("RF Verdict:") ||
                        line.contains("SVM Verdict:") ||
                        line.contains("ELA Result:") ||
                        line.startsWith("[") ||
                        line.startsWith("- ")) {
                    if (!line.startsWith(
                            "ELA_IMAGE_BASE64:") &&
                            !line.contains(
                                    "AI FORENSIC SUMMARY")) {
                        document.add(new Paragraph(
                                line, normalFont));
                    }
                }
            }
            document.add(new Paragraph("\n"));
            document.add(new Paragraph(
                    "DECLARATION", titleFont));
            document.add(new Paragraph(
                    "I certify that findings are true " +
                            "to the best of my knowledge.",
                    normalFont));
            document.add(new Paragraph(
                    "Signature: ______________",
                    normalFont));
            document.add(new Paragraph(
                    "Date: ___________________",
                    normalFont));
        } else {
            document.add(new Paragraph(
                    "FULL DIGITAL FORENSIC METADATA REPORT",
                    titleFont));
            document.add(new Paragraph(
                    "Generated: " + new Date(), normalFont));
            document.add(new Paragraph("\n"));
            for (String line :
                    lastFullReport.split("\n")) {
                if (!line.startsWith("ELA_IMAGE_BASE64:"))
                    document.add(new Paragraph(
                            line, normalFont));
            }
        }
        document.close();
        response.getOutputStream()
                .write(baos.toByteArray());
        response.getOutputStream().flush();
    }

    private String reverseGeocode(
            double lat, double lon
    ) {
        try {
            String url =
                    "https://api.opencagedata.com/" +
                            "geocode/v1/json?q=" +
                            URLEncoder.encode(
                                    lat+","+lon, "UTF-8") +
                            "&key=" + OPENCAGE_KEY;
            Map<?,?> json = new ObjectMapper()
                    .readValue(new URL(url), Map.class);
            List<?> res = (List<?>)json.get("results");
            if (!res.isEmpty())
                return ((Map<?,?>)res.get(0))
                        .get("formatted").toString();
        } catch (Exception ignored) {}
        return "Unknown Location";
    }

    private String classifyMovement(double speed) {
        if (speed > 900)
            return "Impossible Movement (Tampered)";
        if (speed > 300) return "Flight Travel";
        if (speed > 120) return "Vehicle Travel";
        if (speed > 15)  return "Human Movement";
        return "Natural Movement";
    }

    private String classifyArea(String loc) {
        if (loc == null) return "Unknown";
        String t = loc.toLowerCase();
        if (t.contains("college") ||
                t.contains("school"))
            return "Educational Institution";
        if (t.contains("hospital"))
            return "Medical Facility";
        if (t.contains("police") ||
                t.contains("court"))
            return "Restricted Area";
        if (t.contains("mall") ||
                t.contains("market"))
            return "Commercial Area";
        if (t.contains("park") ||
                t.contains("lake"))
            return "Public Area";
        return "General Area";
    }

    private String sha256(File f) throws Exception {
        MessageDigest d =
                MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(f);
        byte[] b = new byte[1024];
        int n;
        while ((n = fis.read(b)) > 0)
            d.update(b, 0, n);
        fis.close();
        StringBuilder s = new StringBuilder();
        for (byte bb : d.digest())
            s.append(String.format("%02x", bb));
        return s.toString();
    }

    private double haversine(
            double la1, double lo1,
            double la2, double lo2
    ) {
        final int R = 6371;
        double dLat = Math.toRadians(la2-la1);
        double dLon = Math.toRadians(lo2-lo1);
        double a =
                Math.sin(dLat/2)*Math.sin(dLat/2) +
                        Math.cos(Math.toRadians(la1)) *
                                Math.cos(Math.toRadians(la2)) *
                                Math.sin(dLon/2)*Math.sin(dLon/2);
        return R*2*Math.atan2(
                Math.sqrt(a), Math.sqrt(1-a));
    }

    private double round(double v) {
        return Math.round(v*100.0)/100.0;
    }

    private String getDimensions(Metadata metadata) {
        try {
            String width = null, height = null;
            for (Directory d :
                    metadata.getDirectories())
                for (Tag t : d.getTags()) {
                    if (t.getTagName()
                            .equalsIgnoreCase(
                                    "Image Width"))
                        width = t.getDescription();
                    if (t.getTagName()
                            .equalsIgnoreCase(
                                    "Image Height"))
                        height = t.getDescription();
                }
            if (width != null && height != null)
                return width + " x " + height;
            if (width != null) return width;
        } catch (Exception ignored) {}
        return "Not Available";
    }

    private String safe(String value) {
        return value == null ? "Not Provided" : value;
    }

    static class ImageData {
        Date date; double lat, lon;
        ImageData(Date d, double la, double lo) {
            date=d; lat=la; lon=lo;
        }
    }
}