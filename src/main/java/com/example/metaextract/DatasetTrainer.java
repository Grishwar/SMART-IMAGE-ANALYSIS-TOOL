package com.example.metaextract;

import java.io.*;
import java.util.*;

public class DatasetTrainer {

    public static void main(String[] args)
            throws Exception {

        String csvPath =
                "C:/Users/rajhe/OneDrive/Desktop/" +
                        "VISION DATASET/dataset.csv";

        // Check CSV exists
        File csvFile = new File(csvPath);
        if (!csvFile.exists()) {
            System.out.println(
                    "❌ dataset.csv not found!"
            );
            System.out.println(
                    "Run FeatureExtractor first!"
            );
            return;
        }

        // Read all rows from CSV
        List<double[]> allData =
                new ArrayList<>();
        BufferedReader br =
                new BufferedReader(
                        new FileReader(csvPath)
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

        System.out.println(
                "Total images loaded: " +
                        allData.size()
        );

        if (allData.size() < 10) {
            System.out.println(
                    "❌ Too few images!"
            );
            return;
        }

        // Shuffle
        Collections.shuffle(
                allData, new Random(42)
        );

        // 80/20 split
        int trainSize =
                (int)(allData.size() * 0.8);
        int testSize =
                allData.size() - trainSize;

        double[][] trainData =
                allData.subList(0, trainSize)
                        .toArray(new double[0][]);
        double[][] testData =
                allData.subList(
                        trainSize, allData.size()
                ).toArray(new double[0][]);

        System.out.println(
                "Train size: " + trainSize
        );
        System.out.println(
                "Test size:  " + testSize
        );

        // Train RF
        System.out.println(
                "\nTraining Random Forest..."
        );
        ForensicRandomForest rf =
                new ForensicRandomForest(trainData);
        System.out.println("RF trained ✅");

        // Train SVM
        System.out.println("Training SVM...");
        ForensicSVM svm =
                new ForensicSVM(trainData);
        System.out.println("SVM trained ✅");

        // Test RF
        System.out.println(
                "\n===== RF ACCURACY RESULTS ====="
        );
        evaluate("Random Forest", rf, testData);

        // Test SVM
        System.out.println(
                "\n===== SVM ACCURACY RESULTS ====="
        );
        evaluateSVM("SVM", svm, testData);

        System.out.println(
                "\n✅ Done! Add these accuracy" +
                        " numbers to your viva answer!"
        );
    }

    static void evaluate(
            String name,
            ForensicRandomForest model,
            double[][] testData
    ) {
        int correct=0, tp=0,
                tn=0, fp=0, fn=0;

        for (double[] row : testData) {
            double[] feat =
                    Arrays.copyOf(row, 7);
            int actual = (int) row[7];

            ForensicRandomForest
                    .ForensicResult result =
                    model.predict(feat);
            int predicted =
                    result.isTampered ? 1 : 0;

            if (predicted == actual) correct++;
            if (actual==1 && predicted==1) tp++;
            if (actual==0 && predicted==0) tn++;
            if (actual==0 && predicted==1) fp++;
            if (actual==1 && predicted==0) fn++;
        }

        printResults(
                testData.length, correct,
                tp, tn, fp, fn
        );
    }

    static void evaluateSVM(
            String name,
            ForensicSVM model,
            double[][] testData
    ) {
        int correct=0, tp=0,
                tn=0, fp=0, fn=0;

        for (double[] row : testData) {
            double[] feat =
                    Arrays.copyOf(row, 7);
            int actual = (int) row[7];

            ForensicSVM.SVMResult result =
                    model.predict(feat);
            int predicted =
                    result.isTampered ? 1 : 0;

            if (predicted == actual) correct++;
            if (actual==1 && predicted==1) tp++;
            if (actual==0 && predicted==0) tn++;
            if (actual==0 && predicted==1) fp++;
            if (actual==1 && predicted==0) fn++;
        }

        printResults(
                testData.length, correct,
                tp, tn, fp, fn
        );
    }

    static void printResults(
            int total, int correct,
            int tp, int tn, int fp, int fn
    ) {
        double accuracy =
                (double)correct / total * 100;
        double precision = (tp+fp) > 0 ?
                (double)tp/(tp+fp)*100 : 0;
        double recall = (tp+fn) > 0 ?
                (double)tp/(tp+fn)*100 : 0;
        double f1 = (precision+recall) > 0 ?
                2*precision*recall/
                        (precision+recall) : 0;

        System.out.printf(
                "Accuracy:  %.1f%%%n", accuracy
        );
        System.out.printf(
                "Precision: %.1f%%%n", precision
        );
        System.out.printf(
                "Recall:    %.1f%%%n", recall
        );
        System.out.printf(
                "F1 Score:  %.1f%%%n", f1
        );
        System.out.println(
                "Confusion Matrix:"
        );
        System.out.println(
                "  TP:" + tp +
                        " TN:" + tn +
                        " FP:" + fp +
                        " FN:" + fn
        );
    }
}