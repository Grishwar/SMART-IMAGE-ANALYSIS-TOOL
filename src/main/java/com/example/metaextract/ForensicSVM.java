package com.example.metaextract;

public class ForensicSVM {

    private double[] weights;
    private double bias;
    private static final int FEATURES = 7;
    private static final double LEARNING_RATE = 0.001;
    private static final double LAMBDA = 0.01;
    private static final int EPOCHS = 1000;

    private static final String[] FEATURE_NAMES = {
            "Software Tag",
            "Thumbnail Mismatch",
            "MakerNote Absent",
            "GPS Missing",
            "Timezone Mismatch",
            "Resolution Mismatch",
            "ELA Level"
    };

    // Default constructor
    public ForensicSVM() {
        weights = new double[FEATURES];
        bias = 0;
    }

    // Constructor with real training data
    public ForensicSVM(double[][] trainingData) {
        weights = new double[FEATURES];
        bias = 0;
        train(trainingData);
    }

    // Train using real VISION dataset
    public void train(double[][] data) {
        for (int epoch = 0; epoch < EPOCHS; epoch++) {
            for (double[] row : data) {
                double[] features =
                        new double[FEATURES];
                for (int i = 0; i < FEATURES; i++) {
                    features[i] = row[i];
                }
                double label =
                        row[FEATURES] == 1 ? 1 : -1;
                double decision =
                        dotProduct(features) + bias;

                if (label * decision < 1) {
                    for (int i = 0; i < FEATURES; i++) {
                        weights[i] = weights[i] -
                                LEARNING_RATE * (
                                        2 * LAMBDA * weights[i]
                                                - label * features[i]
                                );
                    }
                    bias = bias +
                            LEARNING_RATE * label;
                } else {
                    for (int i = 0; i < FEATURES; i++) {
                        weights[i] = weights[i] -
                                LEARNING_RATE * (
                                        2 * LAMBDA * weights[i]
                                );
                    }
                }
            }
        }
    }

    // Predict one image
    public SVMResult predict(double[] features) {
        double decision = dotProduct(features) + bias;

        boolean isTampered = decision > 0;

        // Fixed confidence calculation
        double absDecision = Math.abs(decision);
        double confidence = 50 + Math.min(45,
                absDecision * 30);

        double tamperedConf = isTampered ?
                confidence : (100 - confidence);
        double genuineConf = 100 - tamperedConf;

        // Safety bounds
        tamperedConf = Math.min(98,
                Math.max(2, tamperedConf));
        genuineConf = 100 - tamperedConf;

        String verdict;
        if (isTampered && tamperedConf >= 70) {
            verdict = "HIGHLY SUSPICIOUS";
        } else if (isTampered &&
                tamperedConf >= 40) {
            verdict = "Possibly Modified";
        } else if (!isTampered) {
            verdict = "Likely Genuine";
        } else {
            verdict = "Possibly Modified";
        }

        StringBuilder contrib =
                new StringBuilder();
        for (int i = 0; i < FEATURES; i++) {
            if (features[i] > 0 &&
                    weights[i] > 0) {
                double c =
                        features[i] * weights[i] * 100;
                if (c > 1) {
                    contrib.append(FEATURE_NAMES[i])
                            .append(": ")
                            .append(String.format(
                                    "%.1f", c))
                            .append("%\n");
                }
            }
        }

        return new SVMResult(
                isTampered,
                String.format("%.1f", tamperedConf),
                String.format("%.1f", genuineConf),
                verdict,
                contrib.toString().trim()
        );
    }

    private double dotProduct(double[] features) {
        double sum = 0;
        for (int i = 0; i < FEATURES; i++) {
            sum += weights[i] * features[i];
        }
        return sum;
    }

    private double sigmoid(double x) {
        return 1.0 / (1.0 + Math.exp(-x));
    }

    // Result class
    public static class SVMResult {
        public final boolean isTampered;
        public final String tamperedConfidence;
        public final String genuineConfidence;
        public final String verdict;
        public final String featureContribution;

        public SVMResult(
                boolean isTampered,
                String tamperedConf,
                String genuineConf,
                String verdict,
                String featureContribution
        ) {
            this.isTampered = isTampered;
            this.tamperedConfidence = tamperedConf;
            this.genuineConfidence = genuineConf;
            this.verdict = verdict;
            this.featureContribution =
                    featureContribution;
        }
    }
}
