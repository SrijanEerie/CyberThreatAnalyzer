<?php
session_start();

$email = "";
$result = "";

function analyze_email_address_ipqs($email_address) {
    $api_key = //
    $url = "https://ipqualityscore.com/api/json/email/{$api_key}/" . urlencode($email_address);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    curl_close($ch);

    return json_decode($response, true);
}

// On form submit (POST)
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST["email"]);
    $_SESSION['email'] = $email;

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['result'] = "<p style='color:red;'>❌ Invalid email format.</p>";
} else {
    $api_response = analyze_email_address_ipqs($email);

    if (!$api_response || !$api_response['success']) {
        $_SESSION['result'] = "<p style='color:red;'>❌ API request failed. Please check your API key or try again later.</p>";
    } else {
        // Safely extract values
        $valid = $api_response['valid'] ?? false;
        $smtp_score = $api_response['smtp_score'] ?? null;
        $deliverable = ($smtp_score === 3) ? "Yes ✅" : (($smtp_score !== null) ? "No ❌" : "Unknown ❓");

        $disposable = $api_response['disposable'] ?? false;
        $spam_trap_score = $api_response['spam_trap_score'] ?? null;
        $recent_abuse = $api_response['recent_abuse'] ?? false;
        $risk_score = isset($api_response['fraud_score']) ? $api_response['fraud_score'] . " / 100" : 'N/A';
        $first_name = $api_response['first_name'] ?? 'Unknown';
        $domain = $api_response['domain'] ?? 'Unknown';
        $message = $api_response['message'] ?? 'No message';

        $res = "<h4>📊 Email Address Analysis Report</h4><ul style='text-align: left; display: inline-block;'>";
        $res .= "<li><strong>Valid:</strong> " . ($valid ? "Yes ✅" : "No ❌") . "</li>";
        $res .= "<li><strong>Deliverable (SMTP):</strong> $deliverable</li>";
        $res .= "<li><strong>Disposable:</strong> " . ($disposable ? "Yes ⚠️" : "No ✅") . "</li>";
        
        if ($spam_trap_score !== null) {
            $res .= "<li><strong>Suspected Spam Trap:</strong> " . ($spam_trap_score > 50 ? "Yes 🚫" : "No ✅") . "</li>";
        }

        $res .= "<li><strong>Recent Abuse:</strong> " . ($recent_abuse ? "Yes 🚫" : "No ✅") . "</li>";
        $res .= "<li><strong>Risk Score:</strong> " . htmlspecialchars($risk_score) . "</li>";
        $res .= "<li><strong>First Name:</strong> " . htmlspecialchars($first_name) . "</li>";
        $res .= "<li><strong>Domain:</strong> " . htmlspecialchars($domain) . "</li>";
        $res .= "<li><strong>Message:</strong> " . htmlspecialchars($message) . "</li>";
        $res .= "</ul>";

        $_SESSION['result'] = $res;
    }


    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// On redirect (GET)
if (isset($_SESSION['result'])) {
    $result = $_SESSION['result'];
    unset($_SESSION['result']);
}

if (isset($_SESSION['email'])) {
    $email = $_SESSION['email'];
    unset($_SESSION['email']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Email Analyzer | Cyber Threat Analyzer</title>
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
            background-color: #28a745;
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
        ul li {
            margin-bottom: 5px;
        }
        h4 {
            margin-top: 20px;
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
            <h2>📧 Email Address Analyzer</h2>
            <p>Enter an email address to analyze its reputation and risk.</p>
            <form method="POST" action="">
                <input type="text" name="email" placeholder="Enter email address here" value="<?php echo htmlspecialchars($email); ?>" required>
                <br>
                <button type="submit">📧 Analyze Address</button>
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
