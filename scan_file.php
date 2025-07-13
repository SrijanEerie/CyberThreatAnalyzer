<?php
session_start();
session_regenerate_id(true); // Prevent session fixation

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $apiKey =  Replace with your actual VirusTotal API key

    $file = $_FILES['file'];
    $tempPath = $file['tmp_name'];
    $filename = basename($file['name']);

    if ($file['error'] === UPLOAD_ERR_OK) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/files');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, [
            'file' => new CURLFile($tempPath, mime_content_type($tempPath), $filename)
        ]);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'x-apikey: ' . $apiKey
        ]);

        $response = curl_exec($ch);

        if ($response === false) {
            $_SESSION['result'] = "<span style='color:red'>❌ API request failed: " . curl_error($ch) . "</span>";
            curl_close($ch);
            header("Location: scan_file.php");
            exit();
        }

        curl_close($ch);
        $result = json_decode($response, true);
        $scan_id = $result['data']['id'] ?? null;

        if ($scan_id) {
            // Poll until scan completes
            $reportUrl = 'https://www.virustotal.com/api/v3/analyses/' . $scan_id;
            $maxTries = 10;
            $tryCount = 0;
            $reportData = null;

            do {
                sleep(3); // wait between attempts
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $reportUrl);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'x-apikey: ' . $apiKey
                ]);

                $reportResponse = curl_exec($ch);
                curl_close($ch);

                $reportData = json_decode($reportResponse, true);
                $status = $reportData['data']['attributes']['status'] ?? '';

                $tryCount++;
            } while ($status !== 'completed' && $tryCount < $maxTries);

            // Now check the result
            if ($status === 'completed') {
                $stats = $reportData['data']['attributes']['stats'] ?? null;
                $attributes = $reportData['meta']['file_info'] ?? [];

                if ($stats) {
                    $malicious = $stats['malicious'] ?? 0;
                    $suspicious = $stats['suspicious'] ?? 0;
                    $harmless = $stats['harmless'] ?? 0;
                    $undetected = $stats['undetected'] ?? 0;
                    $timeout = $stats['timeout'] ?? 0;

                    $sha256 = $attributes['sha256'] ?? 'N/A';
                    $file_type = $attributes['type_description'] ?? 'Unknown';
                    $scan_date = date("Y-m-d H:i:s");

                    $status_msg = ($malicious > 0 || $suspicious > 0)
                        ? "<span style='color:red;font-weight:bold'>⚠️ Malicious content found</span>"
                        : "<span style='color:green;font-weight:bold'>✅ File appears safe!</span>";

                    $_SESSION['result'] = <<<HTML
                        <div class="alert">
                            {$status_msg}<br><br>
                            <strong>🔍 Scan Summary:</strong><br>
                            • Malicious: {$malicious} engine(s)<br>
                            • Suspicious: {$suspicious} engine(s)<br>
                            • Harmless: {$harmless} engine(s)<br>
                            • Undetected: {$undetected} engine(s)<br>
                            • Timeout: {$timeout} engine(s)<br><br>
                            <strong>📁 File Info:</strong><br>
                            • File Type: {$file_type}<br>
                            • SHA-256: {$sha256}<br>
                            • Scan Time: {$scan_date}
                        </div>
                    HTML;
                } else {
                    $_SESSION['result'] = "<span style='color:orange'>⚠️ Unable to determine result (no stats available)</span>";
                }
            } else {
                $_SESSION['result'] = "<span style='color:orange'>⚠️ Scan timed out or incomplete</span>";
            }
        } else {
            $_SESSION['result'] = "<span style='color:red'>❌ Failed to upload file for scanning (no scan ID)</span>";
        }
    } else {
        $_SESSION['result'] = "<span style='color:red'>❌ File upload error</span>";
    }

    header("Location: scan_file.php");
    exit();
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>🛡 File Scanner | Cyber Threat Analyzer</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            font-family: 'Inter', sans-serif;
            background: #0f172a;
            color: #f8fafc;
        }
        .navbar {
            background: #1e293b;
            padding: 20px;
            text-align: center;
        }
        .navbar a {
            text-decoration: none;
            color: #38bdf8;
            font-size: 1.6rem;
            font-weight: 700;
        }
        main {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: calc(100vh - 140px);
            padding: 40px 20px;
        }
        h2 {
            font-size: 2.4rem;
            margin-bottom: 10px;
        }
        p {
            font-size: 1.1rem;
            margin-bottom: 25px;
            color: #94a3b8;
        }
        form {
            background: #1e293b;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.2);
            text-align: center;
            width: 100%;
            max-width: 550px;
        }
        .custom-file-upload {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 35px;
            border: 2px dashed #38bdf8;
            border-radius: 15px;
            background: #0f172a;
            color: #94a3b8;
            font-size: 1rem;
            transition: 0.3s ease;
            cursor: pointer;
        }
        .custom-file-upload.dragover {
            border-color: #0ea5e9;
            background-color: #1e293b;
        }
        .custom-file-upload input[type="file"] {
            display: none;
        }
        #file-name-display {
            margin-top: 15px;
            font-size: 0.95rem;
            color: #f1f5f9;
        }
        button {
            margin-top: 25px;
            padding: 12px 30px;
            background: #38bdf8;
            color: #0f172a;
            border: none;
            border-radius: 10px;
            font-weight: bold;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        button:hover {
            background: #0ea5e9;
        }
        .alert {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            font-weight: bold;
        }
        .alert.success {
            background-color: #16a34a;
            color: #fff;
        }
        .alert.error {
            background-color: #dc2626;
            color: #fff;
        }
        footer {
            background-color: #1e293b;
            color: #94a3b8;
            padding: 20px;
            text-align: center;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="page-container">
        <div class="navbar">
            <a href="index.html">🛡 Cyber Threat Analyzer</a>
        </div>
        <main>
            <h2>🗂 File Scanner</h2>
            <p>Upload file for scanning for malicious content.</p>
            <form method="POST" enctype="multipart/form-data" id="file-upload-form">
                <label for="file" class="custom-file-upload" id="drop-area">
                    <span>📁 Click to choose or drag & drop a file</span>
                    <input type="file" name="file" id="file" required>
                </label>
                <p id="file-name-display">No file chosen</p>
                <button type="submit">🔍 Scan File</button>
            </form>
            <center>
           <?php
if (isset($_SESSION['result'])) {
    echo $_SESSION['result'];
    unset($_SESSION['result']);
}
?></center>

        </main>
        <footer>
            <p>© 2025 Cyber Threat Analyzer</p>
            <small> Powered by trusted engines like Google Safe Browsing, VirusTotal, and IPQualityScore.<br>
    Stay informed. Stay secure. Defend against digital threats with Cyber Threat Analyzer.</small>
        </footer>
    </div>

    <script>
        const fileInput = document.getElementById('file');
        const fileNameDisplay = document.getElementById('file-name-display');
        const dropArea = document.getElementById('drop-area');

        fileInput.addEventListener('change', function () {
            if (this.files.length > 0) {
                fileNameDisplay.textContent = `Selected: ${this.files[0].name}`;
            } else {
                fileNameDisplay.textContent = "No file chosen";
            }
        });

        // Drag & Drop Functionality
        dropArea.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropArea.classList.add("dragover");
        });

        dropArea.addEventListener("dragleave", () => {
            dropArea.classList.remove("dragover");
        });

        dropArea.addEventListener("drop", (e) => {
            e.preventDefault();
            dropArea.classList.remove("dragover");

            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                fileNameDisplay.textContent = `Selected: ${files[0].name}`;
            }
        });
    </script>
</body>
</html>
cxswx