# AES-vs-ChaCha20-Streaming
Source code for comparing AES and ChaCha20 in real-time video streaming. Evaluates performance metrics using a Raspberry Pi camera. Includes Python scripts and setup instructions.

Overview
This repository contains the source code for a comparative analysis of the AES and ChaCha20 encryption algorithms in a real-time video streaming application using a Raspberry Pi camera. The project evaluates key performance metrics such as encryption and decryption times and frame rates to determine the most efficient encryption method for streaming applications.

Features
AES and ChaCha20 Encryption: Implements both encryption algorithms in a video streaming context.
Performance Metrics: Tracks and compares metrics like encryption time, decryption time, and frame rate.
Raspberry Pi Compatible: Designed to run with a Raspberry Pi camera module.
Prerequisites
Raspberry Pi 4 Model B
Raspberry Pi Camera Module v2
Python 3.7+
Required Python packages: picamera2, Cryptodome
Installation
Clone the repository:
bash
Copy code
git clone https://github.com/yourusername/AES-vs-ChaCha20-Streaming.git
Navigate to the repository folder and install dependencies:
bash
Copy code
cd AES-vs-ChaCha20-Streaming
pip install -r requirements.txt
Usage
To run the streaming application with AES encryption:

bash
Copy code
python cryptostreamAES.py
To run the streaming application with ChaCha20 encryption:

bash
Copy code
python cryptostreamChaCha20.py
Both scripts will initiate a video stream from the Raspberry Pi camera, encrypt the video frames using the specified algorithm, and serve the encrypted stream to a connected web client.

Contributing
Contributions are welcome! If you have improvements or bug fixes, please fork the repository and submit a pull request.

License
This project is licensed under the MIT License - see the LICENSE.md file for details.
