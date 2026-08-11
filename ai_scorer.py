"""
ai_scorer.py
AI-based steganalysis resistance scorer.

Trains a lightweight neural network to distinguish "clean" images from
"stego" images using statistical LSB-plane features (chi-square statistic,
LSB-plane entropy, sample-pair analysis). Then uses that trained model to
score how detectable a given stego-image is -- simulating an attacker.

Lower score = harder to detect = more secure.
"""

import os
import glob
import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from scipy.stats import chisquare

MODEL_PATH = "model/steganalysis_model.pt"


# ---------------------------------------------------------------------
# Feature extraction (this is what actually makes the AI approach work
# with almost no training data: instead of feeding raw pixels, we feed
# hand-crafted statistical fingerprints known from steganalysis research)
# ---------------------------------------------------------------------

def extract_features(image_path: str) -> np.ndarray:
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img).astype(np.int32)

    features = []
    for channel in range(3):
        plane = arr[:, :, channel]
        lsb_plane = plane & 1

        # 1. LSB plane entropy (random-looking LSBs suggest embedding)
        p1 = np.mean(lsb_plane)
        p0 = 1 - p1
        entropy = -(p1 * np.log2(p1 + 1e-9) + p0 * np.log2(p0 + 1e-9))
        features.append(entropy)

        # 2. Chi-square statistic on pixel value pair frequencies
        #    (classic steganalysis test -- LSB embedding flattens the
        #    natural imbalance between adjacent even/odd pixel values)
        hist, _ = np.histogram(plane.flatten(), bins=256, range=(0, 256))
        even_odd_pairs = hist[::2] + hist[1::2] + 1e-6
        expected = np.full_like(even_odd_pairs, np.mean(even_odd_pairs))
        chi2_stat, _ = chisquare(even_odd_pairs, expected)
        features.append(np.log1p(chi2_stat))

        # 3. Sample pair analysis proxy: correlation between LSB and
        #    second-LSB plane (natural images show more correlation;
        #    LSB embedding weakens it)
        second_lsb = (plane >> 1) & 1
        corr = np.corrcoef(lsb_plane.flatten(), second_lsb.flatten())[0, 1]
        features.append(0.0 if np.isnan(corr) else corr)

    return np.array(features, dtype=np.float32)  # 9 features total


# ---------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------

class SteganalysisNet(nn.Module):
    def __init__(self, input_dim=9):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 1),
            nn.Sigmoid()  # output: probability image is stego
        )

    def forward(self, x):
        return self.net(x)


# ---------------------------------------------------------------------
# Synthetic training: embed random data into a folder of clean images
# to generate cover/stego pairs, then train the classifier on features.
# This avoids needing an external labeled dataset.
# ---------------------------------------------------------------------

def generate_random_binary(length: int) -> str:
    return ''.join(str(np.random.randint(0, 2)) for _ in range(length))


def make_synthetic_stego(image_path: str, out_path: str):
    """Embeds random bits into ~30% of pixels' LSBs to simulate a stego image."""
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    w, h = img.size

    for y in range(h):
        for x in range(w):
            if np.random.rand() < 0.3:
                pixel = list(pixels[x, y])
                for c in range(3):
                    pixel[c] = (pixel[c] & ~1) | np.random.randint(0, 2)
                pixels[x, y] = tuple(pixel)
    img.save(out_path)


def train_scorer(cover_images_dir: str = "uploads", epochs: int = 200):
    """
    Trains the steganalysis model using whatever cover images are available
    in cover_images_dir. Generates synthetic stego versions automatically.
    """
    os.makedirs("model", exist_ok=True)
    os.makedirs("output/synthetic", exist_ok=True)

    image_paths = glob.glob(os.path.join(cover_images_dir, "*.png")) + \
                  glob.glob(os.path.join(cover_images_dir, "*.jpg"))

    if len(image_paths) == 0:
        raise ValueError("No images found in uploads/ to train on. Add a few sample images.")

    X, y = [], []
    for i, path in enumerate(image_paths):
        # Clean (label 0)
        X.append(extract_features(path))
        y.append(0)

        # Synthetic stego (label 1)
        synth_path = f"output/synthetic/synth_{i}.png"
        make_synthetic_stego(path, synth_path)
        X.append(extract_features(synth_path))
        y.append(1)

    X = torch.tensor(np.array(X), dtype=torch.float32)
    y = torch.tensor(np.array(y), dtype=torch.float32).unsqueeze(1)

    # Normalize features
    mean, std = X.mean(0), X.std(0) + 1e-6
    X = (X - mean) / std

    model = SteganalysisNet(input_dim=X.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.BCELoss()

    for epoch in range(epochs):
        optimizer.zero_grad()
        preds = model(X)
        loss = loss_fn(preds, y)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 50 == 0:
            print(f"Epoch {epoch+1}/{epochs} - Loss: {loss.item():.4f}")

    torch.save({"model_state": model.state_dict(), "mean": mean, "std": std}, MODEL_PATH)
    print(f"\n✅ Steganalysis scorer trained and saved to {MODEL_PATH}")
    return model


def score_image(image_path: str) -> float:
    """
    Loads the trained model and scores an image.
    Returns a detectability probability between 0 (undetectable) and 1 (obviously stego).
    """
    if not os.path.exists(MODEL_PATH):
        print("No trained model found -- training now...")
        train_scorer()

    checkpoint = torch.load(MODEL_PATH, weights_only=False)
    model = SteganalysisNet(input_dim=9)
    model.load_state_dict(checkpoint["model_state"])
    model.eval()

    features = extract_features(image_path)
    features = torch.tensor(features, dtype=torch.float32)
    features = (features - checkpoint["mean"]) / checkpoint["std"]

    with torch.no_grad():
        score = model(features.unsqueeze(0)).item()

    return score


# Quick self-test
if __name__ == "__main__":
    print("Training AI steganalysis scorer on sample images...\n")
    train_scorer()

    print("\n--- Scoring your actual stego-image (Step 3 output) ---")
    if os.path.exists("output/stego.png"):
        score = score_image("output/stego.png")
        print(f"Detectability score: {score:.4f}  (0 = undetectable, 1 = clearly stego)")
        if score < 0.5:
            print("✅ AI model judges this stego-image as LOW RISK / hard to detect.")
        else:
            print("⚠️ AI model judges this stego-image as HIGHER RISK — consider embedding fewer bits.")
    else:
        print("Run image_stego.py first to generate output/stego.png")