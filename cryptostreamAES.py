import io
import logging
import socketserver
from http import server
from threading import Condition
from picamera2 import Picamera2
from picamera2.encoders import JpegEncoder
from picamera2.outputs import FileOutput
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64
import time

# Generate encryption key and IV
KEY = get_random_bytes(32)  # AES-256 requires 32 bytes
IV = get_random_bytes(16)   # AES requires 16 bytes IV

PAGE = """
<html>
<head>
    <title>RaspberryTips Pi Cam Stream</title>
    <style>
        .stream-container {{
            display: flex;
            justify-content: space-around;
            margin: 20px;
        }}
        .stream-box {{
            text-align: center;
        }}
        img {{
            max-width: 100%;
            height: auto;
        }}
        .metrics {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin: 20px;
        }}
        .metric-item {{
            display: flex;
            justify-content: space-between;
            margin: 5px 0;
        }}
        .metric-label {{
            font-weight: bold;
            margin-right: 10px;
        }}
        .metric-value {{
            font-family: monospace;
        }}
    </style>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <script>
        // Convert base64 key and IV to WordArray for CryptoJS
        const key = CryptoJS.enc.Base64.parse('{key}');
        const iv = CryptoJS.enc.Base64.parse('{iv}');
        
        // Add performance metrics tracking
        const metrics = {{
            encryptionTime: 0,
            decryptionTime: 0,
            totalFrames: 0,
            avgDecryptionTime: 0,
            avgEncryptionTime: 0,
            lastUpdate: Date.now()
        }};

        function updateMetrics() {{
            document.getElementById('encryption-time').textContent = `${{metrics.encryptionTime.toFixed(2)}} ms`;
            document.getElementById('decryption-time').textContent = `${{metrics.decryptionTime.toFixed(2)}} ms`;
            document.getElementById('avg-encryption-time').textContent = `${{metrics.avgEncryptionTime.toFixed(2)}} ms`;
            document.getElementById('avg-decryption-time').textContent = `${{metrics.avgDecryptionTime.toFixed(2)}} ms`;
            document.getElementById('total-frames').textContent = metrics.totalFrames;
            document.getElementById('fps').textContent = `${{(1000 / ((Date.now() - metrics.lastUpdate) || 1)).toFixed(1)}}`;
            metrics.lastUpdate = Date.now();
        }}

        // Pre-split structure for better performance
        let frameData = {{
            encrypted: null,
            original: null
        }};

        class FrameQueue {{
            constructor(maxSize = 2) {{
                this.queue = new Array(maxSize);
                this.head = 0;
                this.tail = 0;
                this.size = 0;
                this.maxSize = maxSize;
            }}

            push(frame) {{
                if (this.size === this.maxSize) {{
                    this.head = (this.head + 1) % this.maxSize;
                    this.size--;
                }}
                this.queue[this.tail] = frame;
                this.tail = (this.tail + 1) % this.maxSize;
                this.size++;
            }}

            pop() {{
                if (this.size === 0) return null;
                const frame = this.queue[this.head];
                this.head = (this.head + 1) % this.maxSize;
                this.size--;
                return frame;
            }}

            clear() {{
                this.head = 0;
                this.tail = 0;
                this.size = 0;
            }}
        }}

        const frameQueue = new FrameQueue(2);
        let currentBlobUrl = null;
        let decryptionWorker = null;

        function splitFrameData(data) {{
            const parts = data.split('|');
            if (parts.length !== 3) return false;
            
            frameData.encrypted = parts[0];
            frameData.original = parts[1];
            metrics.encryptionTime = parseFloat(parts[2]);
            metrics.totalFrames++;
            metrics.avgEncryptionTime = ((metrics.avgEncryptionTime * (metrics.totalFrames - 1)) + metrics.encryptionTime) / metrics.totalFrames;
            
            return true;
        }}

        async function decryptFrame(encryptedData) {{
            try {{
                const startTime = performance.now();
                
                // Decrypt using AES
                const ciphertext = CryptoJS.enc.Base64.parse(encryptedData);
                const decryptedWA = CryptoJS.AES.decrypt(
                    {{ ciphertext: ciphertext }},
                    key,
                    {{
                        iv: iv,
                        mode: CryptoJS.mode.CBC,
                        padding: CryptoJS.pad.Pkcs7
                    }}
                );
                
                // Convert WordArray to Uint8Array
                const decrypted = new Uint8Array(decryptedWA.sigBytes);
                const words = decryptedWA.words;
                let i = 0;
                for (let w = 0; w < words.length && i < decrypted.length; w++) {{
                    const word = words[w];
                    decrypted[i++] = (word >> 24) & 0xff;
                    if (i < decrypted.length) decrypted[i++] = (word >> 16) & 0xff;
                    if (i < decrypted.length) decrypted[i++] = (word >> 8) & 0xff;
                    if (i < decrypted.length) decrypted[i++] = word & 0xff;
                }}
                
                if (currentBlobUrl) {{
                    URL.revokeObjectURL(currentBlobUrl);
                }}
                
                const blob = new Blob([decrypted], {{type: 'image/jpeg'}});
                currentBlobUrl = URL.createObjectURL(blob);
                
                metrics.decryptionTime = performance.now() - startTime;
                metrics.avgDecryptionTime = ((metrics.avgDecryptionTime * (metrics.totalFrames - 1)) + metrics.decryptionTime) / metrics.totalFrames;
                
                updateMetrics();
                
                return currentBlobUrl;
            }} catch (error) {{
                console.error('Decryption error:', error);
                throw error;
            }}
        }}

        function updateOriginalStream(img, data) {{
            img.src = `data:image/jpeg;base64,${{data}}`;
        }}

        async function processDecryptedStream(img, encryptedData) {{
            frameQueue.push(encryptedData);
            
            if (!decryptionWorker) {{
                decryptionWorker = requestAnimationFrame(async () => {{
                    const frame = frameQueue.pop();
                    frameQueue.clear();
                    
                    if (frame) {{
                        const decryptedUrl = await decryptFrame(frame);
                        img.src = decryptedUrl;
                    }}
                    decryptionWorker = null;
                }});
            }}
        }}

        async function updateImages(originalImg, decryptedImg, data) {{
            if (!splitFrameData(data)) {{
                console.error('Invalid frame data format');
                return;
            }}

            updateOriginalStream(originalImg, frameData.original);
            await processDecryptedStream(decryptedImg, frameData.encrypted);
        }}

        window.addEventListener('unload', () => {{
            if (currentBlobUrl) {{
                URL.revokeObjectURL(currentBlobUrl);
            }}
            if (decryptionWorker) {{
                cancelAnimationFrame(decryptionWorker);
            }}
        }});
    </script>
</head>
<body>
    <h1>Raspberry Pi Camera Live Stream using AES</h1>
    <div class="metrics">
        <h3>Performance Metrics</h3>
        <div class="metric-item">
            <span class="metric-label">Current Encryption Time:</span>
            <span class="metric-value" id="encryption-time">0 ms</span>
        </div>
        <div class="metric-item">
            <span class="metric-label">Current Decryption Time:</span>
            <span class="metric-value" id="decryption-time">0 ms</span>
        </div>
        <div class="metric-item">
            <span class="metric-label">Average Encryption Time:</span>
            <span class="metric-value" id="avg-encryption-time">0 ms</span>
        </div>
        <div class="metric-item">
            <span class="metric-label">Average Decryption Time:</span>
            <span class="metric-value" id="avg-decryption-time">0 ms</span>
        </div>
        <div class="metric-item">
            <span class="metric-label">Total Frames:</span>
            <span class="metric-value" id="total-frames">0</span>
        </div>
        <div class="metric-item">
            <span class="metric-label">Frames Per Second:</span>
            <span class="metric-value" id="fps">0</span>
        </div>
    </div>
    <div class="stream-container">
        <div class="stream-box">
            <h2>Original Stream</h2>
            <img id="original-stream" />
        </div>
        <div class="stream-box">
            <h2>Decrypted Stream</h2>
            <img id="decrypted-stream" />
        </div>
    </div>
    <div id="status">Connecting...</div>
    <script>
        const eventSource = new EventSource('/stream');
        const originalImg = document.getElementById('original-stream');
        const decryptedImg = document.getElementById('decrypted-stream');
        const status = document.getElementById('status');
        
        eventSource.onopen = function() {{
            status.textContent = 'Connected';
        }};
        
        eventSource.onerror = function() {{
            status.textContent = 'Connection error';
        }};
        
        eventSource.onmessage = function(event) {{
            status.textContent = 'Streaming...';
            updateImages(originalImg, decryptedImg, event.data);
        }};
    </script>
</body>
</html>
"""

class StreamingOutput(io.BufferedIOBase):
    def __init__(self):
        self.frame = None
        self.original_frame = None
        self.condition = Condition()
        self.encryption_time = 0
        self._setup_cipher()

    def _setup_cipher(self):
        self.cipher = AES.new(KEY, AES.MODE_CBC, IV)

    def write(self, buf):
        with self.condition:
            try:
                # Add PKCS7 padding
                padding_length = 16 - (len(buf) % 16)
                padded_data = buf + bytes([padding_length] * padding_length)
                
                # Measure encryption time
                start_time = time.perf_counter()
                encrypted_frame = self.cipher.encrypt(padded_data)
                self.encryption_time = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds
                
                self.frame = base64.b64encode(encrypted_frame)
                self.original_frame = base64.b64encode(buf)
                self.condition.notify_all()
            except Exception as e:
                logging.error(f"Encryption error: {str(e)}")
            finally:
                self._setup_cipher()
        return len(buf)

class StreamingHandler(server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.output = output
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.send_response(301)
            self.send_header('Location', '/index.html')
            self.end_headers()
        elif self.path == '/index.html':
            content = PAGE.format(
                key=base64.b64encode(KEY).decode('utf-8'),
                iv=base64.b64encode(IV).decode('utf-8')
            ).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        elif self.path == '/stream':
            self.send_response(200)
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            try:
                while True:
                    with self.output.condition:
                        self.output.condition.wait()
                        if self.output.frame is not None and self.output.original_frame is not None:
                            combined_frame = (
                                self.output.frame + 
                                b'|' + 
                                self.output.original_frame + 
                                b'|' + 
                                str(self.output.encryption_time).encode('utf-8')
                            )
                            self.wfile.write(b'data: ' + combined_frame + b'\n\n')
                            self.wfile.flush()
            except Exception as e:
                logging.warning(
                    'Removed streaming client %s: %s',
                    self.client_address, str(e))
        else:
            self.send_error(404)
            self.end_headers()

class StreamingServer(socketserver.ThreadingMixIn, server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

output = None

if __name__ == '__main__':
    # Initialize camera and server
    picam2 = Picamera2()
    picam2.configure(picam2.create_video_configuration(main={"size": (640, 480)}))
    output = StreamingOutput()
    picam2.start_recording(JpegEncoder(), FileOutput(output))

    try:
        address = ('', 8000)
        server = StreamingServer(address, StreamingHandler)
        print(f"Server started at http://localhost:8000")
        print(f"Using AES-256 with key length: {len(KEY)} bytes")
        print(f"Using IV length: {len(IV)} bytes")
        server.serve_forever()
    finally:
        picam2.stop_recording()
