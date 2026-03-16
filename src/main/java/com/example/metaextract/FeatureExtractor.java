package com.example.metaextract;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifIFD0Directory;
import com.drew.metadata.exif.GpsDirectory;

import java.io.*;

public class FeatureExtractor {

    public static void main(String[] args)
            throws Exception {

        String genuineFolder =
                "C:/Users/rajhe/OneDrive/Desktop/" +
                        "VISION DATASET/GENUINE";
        String tamperedFolder =
                "C:/Users/rajhe/OneDrive/Desktop/" +
                        "VISION DATASET/TAMPERED";
        String outputCSV =
                "C:/Users/rajhe/OneDrive/Desktop/" +
                        "VISION DATASET/dataset.csv";

        PrintWriter writer = new PrintWriter(
                new FileWriter(outputCSV)
        );

        writer.println(
                "filename,softwareScore," +
                        "thumbMismatch,makerNoteAbsent," +
                        "gpsMissing,timezoneMismatch," +
                        "resMismatch,elaLevel,label"
        );

        System.out.println(
                "Reading GENUINE folder..."
        );
        processFolder(genuineFolder, 0, writer);

        System.out.println(
                "Reading TAMPERED folder..."
        );
        processFolder(tamperedFolder, 1, writer);

        writer.close();
        System.out.println(
                "\n✅ dataset.csv created!"
        );
        System.out.println(outputCSV);
    }

    static void processFolder(
            String path,
            int label,
            PrintWriter w
    ) throws Exception {

        File folder = new File(path);
        File[] files = folder.listFiles(
                f -> f.getName().toLowerCase()
                        .matches(".*\\.(jpg|jpeg)")
        );

        if (files == null ||
                files.length == 0) {
            System.out.println(
                    "No images in: " + path
            );
            return;
        }

        int count = 0;
        for (File file : files) {
            try {
                double[] feat =
                        extractFeatures(file);
                w.printf(
                        "%s,%.0f,%.0f,%.0f," +
                                "%.0f,%.0f,%.0f,%.0f,%d%n",
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
                System.out.println(
                        "  ✗ Skip: " +
                                file.getName()
                );
            }
        }
        System.out.println(
                "  Total: " + count + " images\n"
        );
    }

    public static double[] extractFeatures(
            File file
    ) throws Exception {

        double softwareScore    = 0;
        double thumbMismatch    = 0;
        double makerNoteAbsent  = 0; // ✅ FIXED — always 0
        double gpsMissing       = 1;
        double timezoneMismatch = 0;
        double resMismatch      = 0;
        double elaLevel         = 0;

        try {
            Metadata meta =
                    ImageMetadataReader
                            .readMetadata(file);

            // Check Software tag
            ExifIFD0Directory exif0 =
                    meta.getFirstDirectoryOfType(
                            ExifIFD0Directory.class
                    );

            if (exif0 != null) {
                if (exif0.containsTag(
                        ExifIFD0Directory.TAG_SOFTWARE
                )) {
                    String sw = exif0.getString(
                            ExifIFD0Directory.TAG_SOFTWARE
                    ).toLowerCase();

                    if (sw.contains("photoshop") ||
                            sw.contains("gimp") ||
                            sw.contains("lightroom") ||
                            sw.contains("exiftool")) {
                        softwareScore = 2;
                    } else {
                        softwareScore = 1;
                    }
                }
                // MakerNote NOT checked ✅
                // Removed — unreliable feature
                // Lost during USB transfer on
                // all Android devices
                makerNoteAbsent = 0;
            }

            // GPS check
            GpsDirectory gpsDir =
                    meta.getFirstDirectoryOfType(
                            GpsDirectory.class
                    );
            gpsMissing =
                    (gpsDir == null) ? 1 : 0;

            // ELA from file size
            long size = file.length();
            if (size < 100000) {
                elaLevel = 2;
            } else if (size < 300000) {
                elaLevel = 1;
            } else {
                elaLevel = 0;
            }

        } catch (Exception e) {
            gpsMissing     = 1;
            makerNoteAbsent = 0; // ✅ FIXED
            elaLevel       = 1;
        }

        return new double[]{
                softwareScore,    // F0
                thumbMismatch,    // F1
                makerNoteAbsent,  // F2 = always 0
                gpsMissing,       // F3
                timezoneMismatch, // F4
                resMismatch,      // F5
                elaLevel          // F6
        };
    }
}