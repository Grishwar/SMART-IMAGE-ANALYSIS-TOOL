package com.example.metaextract;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifSubIFDDirectory;
import com.drew.metadata.exif.ExifIFD0Directory;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

@RestController
public class FileUploadController {

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "File is empty";
        }
        try {
            String uploadDir = "C:/temp/uploads";
            File dir = new File(uploadDir);
            dir.mkdirs();

            File savedFile = new File(dir, file.getOriginalFilename());
            file.transferTo(savedFile);
            return "File uploaded successfully: " + savedFile.getAbsolutePath();
        } catch (IOException e) {
            return "Failed to save file: " + e.getMessage();
        }
    }

    @GetMapping("/image-date-upload")
    public String getUploadedFileDate(@RequestParam String filename) {
        String uploadDir = "C:/temp/uploads";
        File imageFile = new File(uploadDir, filename);

        if (!imageFile.exists()) {
            return "File not found in uploads directory: " + filename;
        }
        try {
            Metadata metadata = ImageMetadataReader.readMetadata(imageFile);

            ExifSubIFDDirectory dateDirectory = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);
            ExifIFD0Directory modelDirectory = metadata.getFirstDirectoryOfType(ExifIFD0Directory.class);

            StringBuilder response = new StringBuilder();

            // Date with timezone offset correction to avoid wrong future dates
            if (dateDirectory != null) {
                Date originalDate = dateDirectory.getDate(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL);
                if (originalDate != null) {
                    // Example offset fix: subtract 5 hours 30 minutes
                    long offsetMillis = (5 * 60 + 30) * 60 * 1000;
                    Date adjustedDate = new Date(originalDate.getTime() - offsetMillis);

                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    sdf.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
                    response.append("Adjusted Date & Time (IST): ").append(sdf.format(adjustedDate)).append("\n");
                    response.append("Year: ").append(new SimpleDateFormat("yyyy").format(adjustedDate)).append("\n");
                } else {
                    response.append("Date Original metadata not found.\n");
                }
            } else {
                response.append("Exif SubIFD directory not found.\n");
            }

            // Camera Make & Model info
            if (modelDirectory != null) {
                String cameraMake = modelDirectory.getString(ExifIFD0Directory.TAG_MAKE);
                String cameraModel = modelDirectory.getString(ExifIFD0Directory.TAG_MODEL);
                response.append("Camera Make: ").append(cameraMake != null ? cameraMake : "Not found").append("\n");
                response.append("Camera Model: ").append(cameraModel != null ? cameraModel : "Not found");
            } else {
                response.append("Exif IFD0 directory not found.");
            }

            return response.toString();
        } catch (Exception e) {
            return "Error reading metadata: " + e.getMessage();
        }
    }
}
