<?php


// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $fullname = $_POST["fname"];
    $email = $_POST["mail"];
    $mobile = $_POST["phone"];
    $birthdate = $_POST["date"];
    $gender = $_POST["gender"];
    $address = $_POST["cnf"];
    $password = $_POST["pwd"];

    // Use prepared statement to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO registration (fullname, email, mobile, birthdate, gender,cnf, pass) VALUES (?, ?, ?, ?, ?, ?, ?)");
    
    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt->bind_param("sssssss", $fullname, $email, $mobile, $birthdate, $gender, $address, $hashed_password);

    // Execute the prepared statement
    if ($stmt->execute()) {
        // Close the prepared statement
        $stmt->close();
        // Redirect to popup.html with success parameter
        header("Location: popup.html?success=true");
        exit();
    } else {
        echo "Error: " . $stmt->error;
    }
} 


// Close the database connection
$conn->close();
?>
