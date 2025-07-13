<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session
session_start();



// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['uname'];
    $pass = $_POST['pass'];

    // Use prepared statements to prevent SQL injection
    $query = "SELECT * FROM registration WHERE mobile = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $result = $stmt->get_result();

    if (!$result) {
        die("Query failed: " . $conn->error);
    }

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Verify the hashed password
        if (password_verify($pass, $row['pass'])) {
            // Set session variables
            $_SESSION['user'] = $row['mobile'];
            $_SESSION['loggedin'] = true;
            $_SESSION['fullname'] = $row['fullname'] ?? $row['mobile']; // Fallback to mobile if fullname is missing
            header("Location: homepage.php");
            exit();
        } else {
            echo "<script>alert('Invalid credentials');</script>";
        }
    } else {
        echo "<script>alert('Invalid credentials');</script>";
    }

    $stmt->close();
}

// Close the database connection
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LearNexus | Cyber Threat Analyzer</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css"/>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: 'Arial', sans-serif;
    }

    body {
      background: linear-gradient(135deg, #0d1b2a, #1b263b);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      overflow: hidden;
    }

    .wrapper {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 35px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);
      border: 1px solid rgba(255, 255, 255, 0.1);
      position: relative;
      animation: fadeIn 1s ease-in-out;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    h1 {
      color: #00ddeb;
      text-align: center;
      font-size: 2.5em;
      margin-bottom: 10px;
      text-shadow: 0 0 10px rgba(0, 221, 235, 0.5);
    }

    p {
      color: #e0e0e0;
      text-align: center;
      margin-bottom: 20px;
      font-size: 1.1em;
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    input {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 5px;
      padding: 12px;
      color: #fff;
      font-size: 1em;
      outline: none;
      transition: border-color 0.3s ease;
    }

    input:focus {
      border-color: #00ddeb;
      box-shadow: 0 0 8px rgba(0, 221, 235, 0.3);
    }

    input::placeholder {
      color: rgba(255, 255, 255, 0.5);
    }

    .error {
      color: #ff4d4d;
      font-size: 0.9em;
      margin-top: 5px;
      display: block;
    }

    button {
      background: #00ddeb;
      border: none;
      padding: 12px;
      border-radius: 5px;
      color: #0d1b2a;
      font-size: 1.1em;
      font-weight: bold;
      cursor: pointer;
      transition: background 0.3s ease, transform 0.2s ease;
    }

    button:hover {
      background: #00b7c3;
      transform: translateY(-2px);
    }

    .recover {
      text-align: right;
      margin-top: -25px;
    }

    .recover a {
      color: #00ddeb;
      text-decoration: none;
      font-size: 0.9em;
    }

    .recover a:hover {
      text-decoration: underline;
    }

    .or {
      color: #e0e0e0;
      text-align: center;
      margin: 20px 0;
      font-size: 0.9em;
    }

    .icons {
      display: flex;
      justify-content: center;
      gap: 20px;
    }

    .icons i {
      color: #e0e0e0;
      font-size: 1.5em;
      cursor: pointer;
      transition: color 0.3s ease;
    }

    .icons i:hover {
      color: #00ddeb;
    }

    .not-member {
      text-align: center;
      margin-top: 20px;
      color: #e0e0e0;
      font-size: 0.9em;
    }

    .not-member a {
      color: #00ddeb;
      text-decoration: none;
      font-weight: bold;
    }

    .not-member a:hover {
      text-decoration: underline;
    }

    /* Background animation for cybersecurity vibe */
    .bg-animation {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: -1;
      overflow: hidden;
    }

    .bg-animation::before {
      content: '';
      position: absolute;
      width: 200%;
      height: 200%;
      background: radial-gradient(circle, rgba(0, 221, 235, 0.1) 10%, transparent 10.01%);
      background-size: 20px 20px;
      animation: matrix 20s linear infinite;
      opacity: 0.3;
    }

    @keyframes matrix {
      0% { transform: translateY(0); }
      100% { transform: translateY(-50%); }
    }
  </style>
</head>
<body>
  <div class="bg-animation"></div>
  <div class="wrapper">
    <h1> Cyber Threat Analyzer</h1>
    <br><br>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" onsubmit="return validateForm()">
      <label for="uname" class="sr-only">Phone Number</label>
      <input type="tel" placeholder="Enter your Mobile (10 digits)" name="uname" id="uname" required>
      <span class="error" id="unameError"></span>
      <label for="pass" class="sr-only">Password</label>
      <input type="password" placeholder="Password" name="pass" id="pass" required>
      <span class="error" id="passError"></span>
      <p class="recover">
        <a href="forgot.html">Forgot Password?</a>
      </p>
      <button type="submit">Sign In</button>
    </form>
    <p class="or">----- or continue with -----</p>
    <div class="icons">
      <i class="fab fa-google"></i>
      <i class="fab fa-github"></i>
      <i class="fab fa-facebook"></i>
    </div>
    <div class="not-member">
      Not a member? <a href="signup.html">Register Now</a>
    </div>
  </div>

  <script>
    function validateForm() {
      var uname = document.getElementById('uname').value.trim();
      var pass = document.getElementById('pass').value.trim();
      document.getElementById('unameError').innerHTML = "";
      document.getElementById('passError').innerHTML = "";
      var isValid = true;

      if (uname === "") {
        document.getElementById('unameError').innerHTML = "Phone number is required";
        isValid = false;
      } else if (!(/^\d{10}$/.test(uname))) {
        document.getElementById('unameError').innerHTML = "Phone number should be 10 digits";
        isValid = false;
      }

      if (pass === "") {
        document.getElementById('passError').innerHTML = "Password is required";
        isValid = false;
      }

      return isValid;
    }
  </script>
</body>
</html>