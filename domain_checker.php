<?php
session_start();

$result = "";
$domain = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $domain = trim($_POST["domain"]);
    $_SESSION['domain'] = $domain;

    if (!preg_match("/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/", $domain)) {
        $_SESSION['result'] = "<p style='color:red;'>❌ Invalid domain format.</p>";
    } else {
        // Get IP address of domain
        $ip = gethostbyname($domain);

        // Start building result
        $res = "<p style='color:green;'>✅ Domain format is valid.<br>🌐 IP Address: $ip</p>";

        // --------------------- VirusTotal Domain Info ---------------------
        $vtApiKey = ;
        $vtUrl = "https://www.virustotal.com/api/v3/domains/" . urlencode($domain);

        $vtCurl = curl_init($vtUrl);
        curl_setopt($vtCurl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($vtCurl, CURLOPT_HTTPHEADER, ["x-apikey: $vtApiKey"]);
        $vtResponse = curl_exec($vtCurl);
        curl_close($vtCurl);
        $vtData = json_decode($vtResponse, true);

        if (isset($vtData['data'])) {
            $attr = $vtData['data']['attributes'];
            $res .= "<hr><h5>🛡️ VirusTotal Domain Info</h5><ul style='text-align:left;display:inline-block;'>";

            $res .= "<li><strong>Reputation:</strong> " . ($attr['reputation'] ?? 'N/A') . "</li>";
            $res .= "<li><strong>Categories:</strong> " . (isset($attr['categories']) ? implode(', ', $attr['categories']) : 'None') . "</li>";
            $res .= "<li><strong>Registrar:</strong> " . ($attr['registrar'] ?? 'Unknown') . "</li>";
           $creationDate = isset($attr['creation_date']) ? date('Y-m-d', $attr['creation_date']) : 'Unknown';
           $modifiedDate = isset($attr['last_modification_date']) ? date('Y-m-d', $attr['last_modification_date']) : 'Unknown';

$res .= "<li><strong>Creation Date:</strong> $creationDate</li>";
$res .= "<li><strong>Last Modified:</strong> $modifiedDate</li>";

            $res .= "<li><strong>Analysis Stats:</strong><ul>";
            foreach ($attr['last_analysis_stats'] as $k => $v) {
                $res .= "<li>" . ucfirst($k) . ": $v</li>";
            }
            $res .= "</ul></li></ul>";
        } else {
            $res .= "<p style='color:red;'>⚠️ Failed to retrieve VirusTotal info.</p>";
        }

        // --------------------- IPQualityScore IP Reputation ---------------------
        $ipqsKey = ;
        $ipqsUrl = "https://ipqualityscore.com/api/json/ip/$ipqsKey/$ip";

        $ipqsResponse = file_get_contents($ipqsUrl);
        $ipqsData = json_decode($ipqsResponse, true);

        if ($ipqsData && $ipqsData['success']) {
            $res .= "<hr><h5>📊 IPQualityScore IP Reputation</h5><ul style='text-align:left;display:inline-block;'>";
            $res .= "<li><strong>Fraud Score:</strong> " . $ipqsData['fraud_score'] . "/100</li>";
            $res .= "<li><strong>Proxy:</strong> " . ($ipqsData['proxy'] ? 'Yes' : 'No') . "</li>";
            $res .= "<li><strong>VPN:</strong> " . ($ipqsData['vpn'] ? 'Yes' : 'No') . "</li>";
            $res .= "<li><strong>TOR:</strong> " . ($ipqsData['tor'] ? 'Yes' : 'No') . "</li>";
            $res .= "<li><strong>Bot Activity:</strong> " . ($ipqsData['bot_status'] ? 'Yes' : 'No') . "</li>";
            $res .= "</ul>";
        } else {
            $res .= "<p style='color:red;'>⚠️ Failed to retrieve IP reputation from IPQualityScore.</p>";
        }

        $_SESSION['result'] = $res;
    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_SESSION['result'])) {
    $result = $_SESSION['result'];
    unset($_SESSION['result']);
}
if (isset($_SESSION['domain'])) {
    $domain = $_SESSION['domain'];
    unset($_SESSION['domain']);
}
?>




<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Domain Checker | Cyber Threat Analyzer</title>
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
            background-color: #007bff;
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
            <h2>🌐 Domain Checker</h2>
            <p>Enter a domain to check if it's suspicious or safe.</p>
            <form method="POST" action="">
                <input type="text" name="domain" value="<?php echo htmlspecialchars($domain); ?>" placeholder="example.com" required>
                <br>
                <button type="submit">🌐 Check Domain</button>
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
