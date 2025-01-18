import streamlit as st
import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image

# Constants
KEY_LENGTH = 128  # AES Key length (128 bits)


# Function: Preprocess Iris Image
def preprocess_iris(image):
    """
    Preprocess the uploaded iris image by converting to grayscale and resizing.
    """
    image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
    resized_image = cv2.resize(image, (256, 256))  # Standardize size
    return resized_image


# Function: Extract Features Without PCA
def extract_features(image):
    """
    Extract features from the iris image by normalizing pixel values.
    """
    flattened = image.flatten()  # Flatten the 2D image
    normalized = flattened / 255.0  # Normalize pixel values to [0, 1]
    features = normalized[:50]  # Use the first 50 values as features
    return features

# Function: Generate Biometric Key
def generate_biometric_key(features):
    """
    Generate a biometric key from the extracted features.
    Ensure the key length is exactly 16, 24, or 32 bytes for AES encryption.16 bit=128aes
    """
    # Normalize and scale features to integer values
    key = bytes([int(abs(x * 255) % 256) for x in features[:16]])  # Use 16 features for a 16-byte key
    return key

# Function: AES Encryption
def aes_encrypt(data, key):
    """
    Encrypt data using AES with the biometric key.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

# Function: AES Decryption
def aes_decrypt(ciphertext, key):
    """
    Decrypt data using AES with the biometric key.
    """
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

# Streamlit App
def main():
    st.title("Iris Biometric Key Generation and Encryption")
    st.write("Upload an iris image to generate a biometric key and perform AES encryption.")

    # File uploader for iris image
    uploaded_file = st.file_uploader("Upload Iris Image", type=["jpg", "jpeg", "png", "bmp"])

    if uploaded_file is not None:
        # Display uploaded image
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Iris Image", use_column_width=True)

        # Step 1: Preprocess Image
        st.subheader("Preprocessing")
        processed_image = preprocess_iris(image)
        st.image(processed_image, caption="Preprocessed Iris Image", use_column_width=True, channels="GRAY")

        # Step 2: Extract Features
        st.subheader("Feature Extraction")
        features = extract_features(processed_image)
        st.write(f"Extracted Features (First 10): {features[:10]}")

        # Step 3: Generate Biometric Key
        st.subheader("Biometric Key Generation")
        biometric_key = generate_biometric_key(features)
        st.write(f"Generated Biometric Key (Hex): {biometric_key.hex()}")

        # Step 4: AES Encryption
        st.subheader("AES Encryption")
        data_to_encrypt = "Sensitive Information"
        encrypted_data = aes_encrypt(data_to_encrypt, biometric_key)
        st.write(f"Encrypted Data (Hex): {encrypted_data.hex()}")

        # Step 5: AES Decryption
        st.subheader("AES Decryption")
        decrypted_data = aes_decrypt(encrypted_data, biometric_key)
        st.write(f"Decrypted Data: {decrypted_data}")

if __name__ == "__main__":
    main()
