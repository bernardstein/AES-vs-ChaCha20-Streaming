import io
import logging
import socketserver
from http import server
from threading import Condition
from picamera2 import Picamera2
from picamera2.encoders import JpegEncoder
from picamera2.outputs import FileOutput
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes
import base64
import time

# Generate encryption key and nonce
KEY = get_random_bytes(32)
NONCE = get_random_bytes(12)

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
        // Convert base64 key and nonce to Uint8Array
        const key = Uint8Array.from(atob('{key}'), c => c.charCodeAt(0));
        const nonce = Uint8Array.from(atob('{nonce}'), c => c.charCodeAt(0));
        
        class ChaCha20 {{
            constructor(key, nonce) {{
                if (!(key instanceof Uint8Array) || key.length !== 32) {{
                    throw new Error('Key must be 32 bytes');
                }}
                if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {{
                    throw new Error('Nonce must be 12 bytes');
                }}
                this.key = key;
                this.nonce = nonce;
                this.buffer = new Uint8Array(64);
            }}

            static rotl(a, b) {{
                return (a << b) | (a >>> (32 - b));
            }}

            static quarterRound(state, a, b, c, d) {{
                state[a] += state[b]; state[d] ^= state[a]; state[d] = ChaCha20.rotl(state[d], 16);
                state[c] += state[d]; state[b] ^= state[c]; state[b] = ChaCha20.rotl(state[b], 12);
                state[a] += state[b]; state[d] ^= state[a]; state[d] = ChaCha20.rotl(state[d], 8);
                state[c] += state[d]; state[b] ^= state[c]; state[b] = ChaCha20.rotl(state[b], 7);
            }}

            chacha20Block(counter) {{
                const state = new Uint32Array(16);
                
                state[0] = 0x61707865;
                state[1] = 0x3320646e;
                state[2] = 0x79622d32;
                state[3] = 0x6b206574;

                for (let i = 0; i < 8; i++) {{
                    state[4 + i] = (this.key[4*i + 3] << 24) | 
                                 (this.key[4*i + 2] << 16) | 
                                 (this.key[4*i + 1] << 8) | 
                                 this.key[4*i];
                }}

                state[12] = counter;
                state[13] = (this.nonce[3] << 24) | (this.nonce[2] << 16) | (this.nonce[1] << 8) | this.nonce[0];
                state[14] = (this.nonce[7] << 24) | (this.nonce[6] << 16) | (this.nonce[5] << 8) | this.nonce[4];
                state[15] = (this.nonce[11] << 24) | (this.nonce[10] << 16) | (this.nonce[9] << 8) | this.nonce[8];

                const working = new Uint32Array(state);

                for (let i = 0; i < 10; i++) {{
                    ChaCha20.quarterRound(working, 0, 4, 8, 12);
                    ChaCha20.quarterRound(working, 1, 5, 9, 13);
                    ChaCha20.quarterRound(working, 2, 6, 10, 14);
                    ChaCha20.quarterRound(working, 3, 7, 11, 15);
                    ChaCha20.quarterRound(working, 0, 5, 10, 15);
                    ChaCha20.quarterRound(working, 1, 6, 11, 12);
                    ChaCha20.quarterRound(working, 2, 7, 8, 13);
                    ChaCha20.quarterRound(working, 3, 4, 9, 14);
                }}

                for (let i = 0; i < 16; i++) {{
                    working[i] += state[i];
                }}

                for (let i = 0; i < 16; i++) {{
                    this.buffer[4*i] = working[i] & 0xff;
                    this.buffer[4*i + 1] = (working[i] >>> 8) & 0xff;
                    this.buffer[4*i + 2] = (working[i] >>> 16) & 0xff;
                    this.buffer[4*i + 3] = (working[i] >>> 24) & 0xff;
                }}
                
                return this.buffer;
            }}

            decrypt(data) {{
                const result = new Uint8Array(data.length);
                let counter = 0;
                
                const chunkSize = 64 * 1024;
                for (let offset = 0; offset < data.length; offset += chunkSize) {{
                    const chunk = data.slice(offset, offset + chunkSize);
                    let pos = 0;
                    
                    while (pos < chunk.length) {{
                        const keyStream = this.chacha20Block(counter++);
                        const blockSize = Math.min(64, chunk.length - pos);
                        for (let i = 0; i < blockSize; i++) {{
                            result[offset + pos + i] = chunk[pos + i] ^ keyStream[i];
                        }}
                        pos += 64;
                    }}
                }}
                
                return result;
            }}
        }}
        
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

        // Maintain separate workers for encrypted and original streams
        let decryptionWorker = null;
        let displayWorker = null;

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
        const chacha = new ChaCha20(key, nonce);
        let currentBlobUrl = null;

        function splitFrameData(data) {{
            const parts = data.split('|');
            if (parts.length !== 3) return false;
            
            frameData.encrypted = parts[0];
            frameData.original = parts[1];
            // Update encryption time metrics
            metrics.encryptionTime = parseFloat(parts[2]);
            metrics.totalFrames++;
            metrics.avgEncryptionTime = ((metrics.avgEncryptionTime * (metrics.totalFrames - 1)) + metrics.encryptionTime) / metrics.totalFrames;
            
            return true;
        }}

        async function decryptFrame(encryptedData) {{
            try {{
                const startTime = performance.now();
                
                const binary = atob(encryptedData);
                const length = binary.length;
                const encrypted = new Uint8Array(length);
                for (let i = 0; i < length; i++) {{
                    encrypted[i] = binary.charCodeAt(i);
                }}
                
                const decrypted = chacha.decrypt(encrypted);
                
                if (currentBlobUrl) {{
                    URL.revokeObjectURL(currentBlobUrl);
                }}
                
                const blob = new Blob([decrypted], {{type: 'image/jpeg'}});
                currentBlobUrl = URL.createObjectURL(blob);
                
                // Update decryption metrics
                metrics.decryptionTime = performance.now() - startTime;
                metrics.totalFrames++;
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
            if (displayWorker) {{
                cancelAnimationFrame(displayWorker);
            }}
        }});
    </script>
</head>
<body>
    <h1>Raspberry Pi Camera Live Stream using ChaCha20</h1>
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

import time

class StreamingOutput(io.BufferedIOBase):
    def __init__(self):
        self.frame = None
        self.original_frame = None
        self.condition = Condition()
        self.encryption_time = 0
        self._setup_cipher()

    def _setup_cipher(self):
        self.cipher = ChaCha20.new(key=KEY, nonce=NONCE)

    def write(self, buf):
        with self.condition:
            try:
                # Measure encryption time
                start_time = time.perf_counter()
                encrypted_frame = self.cipher.encrypt(buf)
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
                nonce=base64.b64encode(NONCE).decode('utf-8')
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
                            # Include encryption time in the data stream
                            # Format: encrypted_frame|original_frame|encryption_time
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
        address = ('', 8001)
        server = StreamingServer(address, StreamingHandler)
        print(f"Server started at http://localhost:8001")
        print(f"Using key length: {len(KEY)} bytes")
        print(f"Using nonce length: {len(NONCE)} bytes")
        server.serve_forever()
    finally:
        picam2.stop_recording()
