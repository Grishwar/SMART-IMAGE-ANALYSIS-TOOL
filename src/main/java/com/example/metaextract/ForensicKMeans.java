package com.example.metaextract;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ============================================================
 * K-MEANS CLUSTERING — Multi-Image Forensic Grouping
 * ============================================================
 * Groups multiple uploaded images into clusters based on:
 * - GPS location similarity
 * - Capture time proximity
 * - Risk score similarity
 * - Camera device similarity
 *
 * USE CASE:
 * When 3+ images uploaded, finds:
 * - Images taken from same location
 * - Images taken by same device
 * - Suspicious outlier images
 * ============================================================
 */
public class ForensicKMeans {

    private static final int MAX_ITERATIONS = 100;

    // ============================================================
    // IMAGE DATA POINT for clustering
    // ============================================================
    public static class ImagePoint {
        public String fileName;
        public double lat;
        public double lon;
        public double riskScore;
        public double captureHour;    // 0-23
        public int clusterId = -1;

        public ImagePoint(String fileName, double lat, double lon,
                          double riskScore, double captureHour) {
            this.fileName = fileName;
            this.lat = lat;
            this.lon = lon;
            this.riskScore = riskScore;
            this.captureHour = captureHour;
        }

        // Returns normalized feature vector [lat, lon, risk, hour]
        public double[] toFeatureVector() {
            return new double[]{
                    lat / 90.0,           // Normalize lat to 0-1
                    lon / 180.0,          // Normalize lon to 0-1
                    riskScore / 100.0,    // Normalize risk to 0-1
                    captureHour / 24.0    // Normalize hour to 0-1
            };
        }
    }

    // Cluster result
    public static class ClusterResult {
        public int clusterId;
        public List<String> fileNames = new ArrayList<>();
        public String description;
        public String suspicionLevel;

        public ClusterResult(int id) { this.clusterId = id; }
    }

    // ============================================================
    // MAIN CLUSTER METHOD
    // ============================================================
    public static List<ClusterResult> cluster(List<ImagePoint> points) {
        if (points == null || points.size() < 2) return new ArrayList<>();

        // Determine optimal K
        int k = determineK(points.size());

        // Initialize centroids using K-Means++ strategy
        double[][] centroids = initializeCentroids(points, k);

        // Run K-Means iterations
        for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
            // Assign each point to nearest centroid
            boolean changed = assignClusters(points, centroids);

            // Recalculate centroids
            recalculateCentroids(points, centroids, k);

            // Stop if no assignments changed
            if (!changed) break;
        }

        // Build result
        return buildResults(points, k);
    }

    // Determine K based on number of images
    private static int determineK(int n) {
        if (n <= 2) return 1;
        if (n <= 4) return 2;
        if (n <= 8) return 3;
        return Math.min(4, n / 2);
    }

    // K-Means++ initialization — spread initial centroids
    private static double[][] initializeCentroids(List<ImagePoint> points, int k) {
        double[][] centroids = new double[k][4];

        // First centroid — random point
        double[] first = points.get(0).toFeatureVector();
        centroids[0] = first;

        // Remaining centroids — pick points far from existing centroids
        for (int i = 1; i < k; i++) {
            double maxDist = -1;
            int bestIdx = 0;

            for (int j = 0; j < points.size(); j++) {
                double minDist = Double.MAX_VALUE;
                double[] fv = points.get(j).toFeatureVector();

                for (int c = 0; c < i; c++) {
                    double d = euclideanDistance(fv, centroids[c]);
                    if (d < minDist) minDist = d;
                }

                if (minDist > maxDist) {
                    maxDist = minDist;
                    bestIdx = j;
                }
            }
            centroids[i] = points.get(bestIdx).toFeatureVector();
        }

        return centroids;
    }

    // Assign each point to nearest centroid
    private static boolean assignClusters(List<ImagePoint> points, double[][] centroids) {
        boolean changed = false;

        for (ImagePoint point : points) {
            double minDist = Double.MAX_VALUE;
            int bestCluster = 0;
            double[] fv = point.toFeatureVector();

            for (int c = 0; c < centroids.length; c++) {
                double dist = euclideanDistance(fv, centroids[c]);
                if (dist < minDist) {
                    minDist = dist;
                    bestCluster = c;
                }
            }

            if (point.clusterId != bestCluster) {
                point.clusterId = bestCluster;
                changed = true;
            }
        }

        return changed;
    }

    // Recalculate centroid as mean of all points in cluster
    private static void recalculateCentroids(List<ImagePoint> points,
                                             double[][] centroids, int k) {
        int[] counts = new int[k];
        double[][] sums = new double[k][4];

        for (ImagePoint point : points) {
            if (point.clusterId >= 0 && point.clusterId < k) {
                double[] fv = point.toFeatureVector();
                for (int f = 0; f < 4; f++) {
                    sums[point.clusterId][f] += fv[f];
                }
                counts[point.clusterId]++;
            }
        }

        for (int c = 0; c < k; c++) {
            if (counts[c] > 0) {
                for (int f = 0; f < 4; f++) {
                    centroids[c][f] = sums[c][f] / counts[c];
                }
            }
        }
    }

    // Build human readable cluster results
    private static List<ClusterResult> buildResults(List<ImagePoint> points, int k) {
        Map<Integer, ClusterResult> resultMap = new HashMap<>();

        for (int i = 0; i < k; i++) {
            resultMap.put(i, new ClusterResult(i));
        }

        for (ImagePoint point : points) {
            if (point.clusterId >= 0) {
                resultMap.get(point.clusterId).fileNames.add(point.fileName);
            }
        }

        // Generate descriptions for each cluster
        for (Map.Entry<Integer, ClusterResult> entry : resultMap.entrySet()) {
            ClusterResult cr = entry.getValue();
            List<ImagePoint> clusterPoints = new ArrayList<>();

            for (ImagePoint p : points) {
                if (p.clusterId == entry.getKey()) clusterPoints.add(p);
            }

            if (!clusterPoints.isEmpty()) {
                // Calculate average risk for cluster
                double avgRisk = 0;
                for (ImagePoint p : clusterPoints) avgRisk += p.riskScore;
                avgRisk /= clusterPoints.size();

                // Check GPS proximity
                boolean sameLocation = isLocationSimilar(clusterPoints);

                // Build description
                StringBuilder desc = new StringBuilder();
                desc.append("Group ").append(cr.clusterId + 1).append(": ");
                desc.append(cr.fileNames.size()).append(" image(s) — ");

                if (sameLocation && cr.fileNames.size() > 1) {
                    desc.append("Taken at same/nearby location. ");
                }
                if (avgRisk > 50) {
                    desc.append("HIGH risk group — multiple suspicious indicators. ");
                    cr.suspicionLevel = "HIGH";
                } else if (avgRisk > 20) {
                    desc.append("MEDIUM risk group — some indicators present. ");
                    cr.suspicionLevel = "MEDIUM";
                } else {
                    desc.append("LOW risk group — appears genuine. ");
                    cr.suspicionLevel = "LOW";
                }

                cr.description = desc.toString();
            }
        }

        // Remove empty clusters
        List<ClusterResult> results = new ArrayList<>();
        for (ClusterResult cr : resultMap.values()) {
            if (!cr.fileNames.isEmpty()) results.add(cr);
        }

        return results;
    }

    // Check if all points in cluster are from same/nearby location (within 10km)
    private static boolean isLocationSimilar(List<ImagePoint> points) {
        if (points.size() < 2) return true;
        ImagePoint first = points.get(0);
        for (ImagePoint p : points) {
            double dist = haversine(first.lat, first.lon, p.lat, p.lon);
            if (dist > 10) return false; // More than 10km apart
        }
        return true;
    }

    // Haversine distance in km
    private static double haversine(double lat1, double lon1,
                                    double lat2, double lon2) {
        final int R = 6371;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(lat1)) *
                        Math.cos(Math.toRadians(lat2)) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }

    // Euclidean distance between feature vectors
    private static double euclideanDistance(double[] a, double[] b) {
        double sum = 0;
        for (int i = 0; i < a.length; i++) {
            sum += Math.pow(a[i] - b[i], 2);
        }
        return Math.sqrt(sum);
    }

    // ============================================================
    // FORMAT RESULTS as String for report
    // ============================================================
    public static String formatResults(List<ClusterResult> results) {
        if (results.isEmpty()) return "Clustering requires minimum 2 images with GPS data.\n";

        StringBuilder sb = new StringBuilder();
        sb.append("\n=========== K-MEANS CLUSTER ANALYSIS ===========\n");
        sb.append("Total Groups Found: ").append(results.size()).append("\n\n");

        for (ClusterResult cr : results) {
            sb.append(cr.description).append("\n");
            sb.append("Images in this group:\n");
            for (String f : cr.fileNames) {
                sb.append("  - ").append(f).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }
}