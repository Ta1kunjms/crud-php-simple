<?php
// Include the database connection file
require_once("dbConnection.php");

$errors = array();
$successMessage = "";

if (isset($_POST['update'])) {
	// Escape special characters in a string for use in an SQL statement
	$id = (int) $_POST['id'];
	$name = mysqli_real_escape_string($mysqli, $_POST['name']);
	$age = mysqli_real_escape_string($mysqli, $_POST['age']);
	$email = mysqli_real_escape_string($mysqli, $_POST['email']);	
	
	// Check for empty fields
	if (empty($name) || empty($age) || empty($email)) {
		if (empty($name)) {
			$errors[] = "Name field is empty.";
		}
		
		if (empty($age)) {
			$errors[] = "Age field is empty.";
		}
		
		if (empty($email)) {
			$errors[] = "Email field is empty.";
		}
	} else {
		// Update the database table
		$result = mysqli_query($mysqli, "UPDATE users SET `name` = '$name', `age` = '$age', `email` = '$email' WHERE `id` = $id");
		
		$successMessage = "Data updated successfully!";
	}
}

if (!isset($_POST['update'])) {
	header("Location:index.php");
	exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Edit User Result</title>
	<link rel="stylesheet" href="styles.css">
</head>
<body>
	<div class="page-wrapper">
		<header class="topbar">
			<div>
				<h1>Edit User</h1>
				<p class="subtitle">Update status</p>
			</div>
			<div class="credit">TYCOON JAMES FLORES</div>
		</header>

		<main class="card">
			<?php
			if (!empty($errors)) {
				echo "<div class='message message-error'>";
				echo "<strong>Please fix the following:</strong><ul>";
				foreach ($errors as $error) {
					echo "<li>" . htmlspecialchars($error) . "</li>";
				}
				echo "</ul></div>";
				echo "<a class='btn btn-soft' href='javascript:self.history.back();'>Go Back</a>";
			} else {
				echo "<div class='message message-success'><strong>" . htmlspecialchars($successMessage) . "</strong></div>";
				echo "<a class='btn btn-primary' href='index.php'>View Dashboard</a>";
			}
			?>
		</main>
	</div>
</body>
</html>
