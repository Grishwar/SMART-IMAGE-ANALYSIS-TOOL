package com.example.metaextract;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifIFD0Directory;
import com.drew.metadata.exif.GpsDirectory;

public class FeatureExtractor {

    public static void main(String[] args) throws Exception {

        // ── CHANGE: Paths now use args[] so you can run from anywhere ──
        // Usage: java FeatureExtractor <genuineFolder> <tamperedFolder> <outputCSV>
        // Example: java FeatureExtractor "D:/VISION DATASET/GENUINE" "D:/VISION DATASET/TAMPERED" "src/main/resources/dataset.csv"
        //
        // If no args given, falls back to asking for path or using current dir

        String genuineFolder;
        String tamperedFolder;
        String outputCSV;

        if (args.length >= 3) {
            genuineFolder = args[0];
            tamperedFolder = args[1];
            outputCSV = args[2];
        } else {
            // ── CHANGE: Default output goes directly into src/main/resources ──
            // This means after running, dataset.csv is already in the right place
            // Change only these 3 lines to match your actual VISION DATASET folder location
            genuineFolder  = System.getProperty("user.home") + "/VISION DATASET/GENUINE";
            tamperedFolder = System.getProperty("user.home") + "/VISION DATASET/TAMPERED";
            outputCSV      = "src/main/resources/dataset.csv";

            System.out.println("No args provided. Using default paths:");
            System.out.println("  Genuine:  " + genuineFolder);
            System.out.println("  Tampered: " + tamperedFolder);
            System.out.println("  Output:   " + outputCSV);
            System.out.println();
            System.out.println("To override: java FeatureExtractor <genuineFolder> <tamperedFolder> <outputCSV>");
            System.out.println();
        }

        PrintWriter writer = new PrintWriter(new FileWriter(outputCSV));
        writer.println(
                "filename,softwareScore,thumbMismatch,makerNoteAbsent," +
                        "gpsMissing,timezoneMismatch,resMismatch,elaLevel,label"
        );

        System.out.println("Reading GENUINE folder: " + genuineFolder);
        processFolder(genuineFolder, 0, writer);

        System.out.println("Reading TAMPERED folder: " + tamperedFolder);
        processFolder(tamperedFolder, 1, writer);

        writer.close();
        System.out.println("\n✅ dataset.csv created at: " + outputCSV);
        System.out.println("If output was src/main/resources/dataset.csv, you're ready to deploy!");
    }

    static void processFolder(String path, int label, PrintWriter w) throws Exception {
        File folder = new File(path);
        File[] files = folder.listFiles(
                f -> f.getName().toLowerCase().matches(".*\\.(jpg|jpeg)")
        );

        if (files == null || files.length == 0) {
            System.out.println("No images in: " + path);
            return;
        }

        int count = 0;
        for (File file : files) {
            try {
                double[] feat = extractFeatures(file);
                w.printf(
                        "%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%d%n",
                        file.getName(),
                        feat[0], feat[1], feat[2],
                        feat[3], feat[4], feat[5],
                        feat[6], label
                );
                count++;
                System.out.println(
                        "  ✓ " + file.getName() +
                                " | GPS:" + (int)feat[3] +
                                " | ELA:" + (int)feat[6] +
                                " | Label:" + label
                );
            } catch (Exception e) {
                System.out.println("  ✗ Skip: " + file.getName());
            }
        }
        System.out.println("  Total: " + count + " images\n");
    }

    public static double[] extractFeatures(File file) throws Exception {
        double softwareScore    = 0;
        double thumbMismatch    = 0;
        double makerNoteAbsent  = 0;
        double gpsMissing       = 1;
        double timezoneMismatch = 0;
        double resMismatch      = 0;
        double elaLevel         = 0;

        try {
            Metadata meta = ImageMetadataReader.readMetadata(file);

            ExifIFD0Directory exif0 = meta.getFirstDirectoryOfType(ExifIFD0Directory.class);
            if (exif0 != null) {
                if (exif0.containsTag(ExifIFD0Directory.TAG_SOFTWARE)) {
                    String sw = exif0.getString(ExifIFD0Directory.TAG_SOFTWARE).toLowerCase();
                    if (sw.contains("photoshop") || sw.contains("gimp") ||
                            sw.contains("lightroom") || sw.contains("exiftool")) {
                        softwareScore = 2;
                    } else {
                        softwareScore = 1;
                    }
                }
                makerNoteAbsent = 0; // Removed — unreliable on Android USB transfers
            }

            GpsDirectory gpsDir = meta.getFirstDirectoryOfType(GpsDirectory.class);
            gpsMissing = (gpsDir == null) ? 1 : 0;

            // ELA approximation from file size
            long size = file.length();
            if (size < 100000)      { elaLevel = 2; }
            else if (size < 300000) { elaLevel = 1; }
            else                    { elaLevel = 0; }

        } catch (Exception e) {
            gpsMissing      = 1;
            makerNoteAbsent = 0;
            elaLevel        = 1;
        }

        return new double[]{
                softwareScore,    // F0
                thumbMismatch,    // F1
                makerNoteAbsent,  // F2
                gpsMissing,       // F3
                timezoneMismatch, // F4
                resMismatch,      // F5
                elaLevel          // F6
        };
    }
}