package com.example.metaextract;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifSubIFDDirectory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.Date;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "Welcome to Metaextract Application!";
    }

    @GetMapping("/image-date")
    public String getImageDate(@RequestParam String imagePath) {
        try {
            File imageFile = new File(imagePath);
            if (!imageFile.exists() || !imageFile.isFile()) {
                return "File not found or invalid: " + imagePath;
            }

            Metadata metadata = ImageMetadataReader.readMetadata(imageFile);
            ExifSubIFDDirectory directory = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);

            if (directory != null) {
                Date date = directory.getDateOriginal();
                if (date != null) {
                    return "Date/Time Original: " + date.toString();
                } else {
                    return "Date/Time Original metadata not found.";
                }
            } else {
                return "Exif SubIFD directory not found.";
            }
        } catch (Exception e) {
            return "Error reading metadata: " + e.getMessage();
        }
    }
}
