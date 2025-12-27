package com.example.metaextract;

import java.io.File;
import java.util.Date;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifSubIFDDirectory;

public class ImageMetadataController {

    public static void main(String[] args) {
        try {
            // Change this path to the image file path on your system
            File imageFile = new File("path_to_your_image.jpg");

            Metadata metadata = ImageMetadataReader.readMetadata(imageFile);

            // Extract the ExifSubIFDDirectory which contains Date/Time Original tag
            ExifSubIFDDirectory directory = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);

            if (directory != null) {
                // Date/Time original tag (tag 0x9003)
                Date date = directory.getDateOriginal();

                if (date != null) {
                    System.out.println("Date/Time Original: " + date.toString());
                } else {
                    System.out.println("Date/Time Original metadata not found.");
                }
            } else {
                System.out.println("Exif SubIFD directory not found.");
            }
        } catch (Exception e) {
            System.err.println("Error reading metadata: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
