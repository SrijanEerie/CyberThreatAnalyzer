<?php
session_start();

$result = "";
$url = "";

// Function to check URL
function checkWithSafeBrowsingAPI($url, $apiKey) {
    $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" . $apiKey;

    $body = [
        "client" => [
            "clientId" => "cyber-threat-analyzer",
            "clientVersion" => "1.0"
        ],
        "threatInfo" => [
            "threatTypes" => ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes" => ["ANY_PLATFORM"],
            "threatEntryTypes" => ["URL"],
            "threatEntries" => [
                ["url" => $url]
            ]
        ]
    ];

    $options = [
        'http' => [
            'header'  => "Content-type: application/json\r\n",
            'method'  => 'POST',
            'content' => json_encode($body),
            'timeout' => 5
        ]
    ];

    $context = stream_context_create($options);
    $response = file_get_contents($endpoint, false, $context);

    if ($response === FALSE) {
        return "<p style='color:red;'>⚠️ Error: Unable to contact Safe Browsing API.</p>";
    }

    $data = json_decode($response, true);
    if (!empty($data['matches'])) {
        return "<p style='color:red;'>🚨 Unsafe URL detected (phishing/malware)!</p>";
    } else {
        return "<p style='color:green;'>✅ This URL appears safe.</p>";
    }
}

// On form submit
// On form submit
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $url = trim($_POST["url"]);
    $_SESSION['url'] = $url;

    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        $_SESSION['result'] = "<p style='color:red;'>❌ Invalid URL format.</p>";
    } else {
        $parsed = parse_url($url);
        $domain = $parsed['host'] ?? '';

        if (empty($domain) || !checkdnsrr($domain, 'A')) {
            $_SESSION['result'] = "<p style='color:red;'>❌ Invalid or unreachable domain.</p>";
        } else {
            $apiKey = ;
            $_SESSION['result'] = checkWithSafeBrowsingAPI($url, $apiKey);
        }
    }

    // Redirect using PRG
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}


// On GET (after redirect)
if (isset($_SESSION['result'])) {
    $result = $_SESSION['result'];
    unset($_SESSION['result']);
}

if (isset($_SESSION['url'])) {
    $url = $_SESSION['url'];
    unset($_SESSION['url']); // clear after one use
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>URL Scanner | Cyber Threat Analyzer</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        html, body {
            height: 100%;
            margin: 0;
        }

        .page-container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        main {
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 30px 15px;
            text-align: center;
        }

        input[type="text"] {
            width: 100%;
            max-width: 500px;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }

        button {
            padding: 10px 25px;
            border: none;
            background-color: #dc3545;
            color: white;
            border-radius: 5px;
        }

        footer {
            background-color: #1f1f1f;
            color: white;
            padding: 20px 0;
            text-align: center;
        }

        .navbar {
            background-color: #1f1f1f;
        }

        .navbar .navbar-brand {
            color: white;
            font-weight: bold;
        }

        h2 {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="page-container">
        <!-- Navbar -->
        <nav class="navbar">
            <div class="container">
                <a class="navbar-brand" href="index.html">🛡️ Cyber Threat Analyzer</a>
            </div>
        </nav>

        <!-- Main Content -->
        <main>
            <h2>🔍 URL Scanner</h2>
            <p>Enter a URL to scan for phishing or malware.</p>
            <form method="POST" action="">
                <input type="text" name="url" value="<?php echo htmlspecialchars($url); ?>" placeholder="https://example.com" required>
                <br>
                <button type="submit">🔍 Check</button>
            </form>
            <br>
            <?php echo $result; ?>
        </main>

        <!-- Footer -->
        <footer>
            <div class="container">
                <p>© 2025 Cyber Threat Analyzer</p>
                <small> Powered by trusted engines like Google Safe Browsing, VirusTotal, and IPQualityScore.<br>
    Stay informed. Stay secure. Defend against digital threats with Cyber Threat Analyzer.</small>
            </div>
        </footer>
    </div>
</body>
</html>
