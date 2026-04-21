<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Add User Result</title>
	<link rel="stylesheet" href="styles.css">
</head>

<body>
	<div class="page-wrapper">
		<header class="topbar">
			<div>
				<h1>Add User</h1>
				<p class="subtitle">Submission status</p>
			</div>
			<div class="credit">TYCOON JAMES FLORES</div>
		</header>

		<main class="card">
			<?php
			// Include the database connection file
			require_once("dbConnection.php");

			if (isset($_POST['submit'])) {
				// Escape special characters in string for use in SQL statement
				$name = mysqli_real_escape_string($mysqli, $_POST['name']);
				$age = mysqli_real_escape_string($mysqli, $_POST['age']);
				$email = mysqli_real_escape_string($mysqli, $_POST['email']);

				$errors = array();

				if (empty($name)) {
					$errors[] = "Name field is empty.";
				}

				if (empty($age)) {
					$errors[] = "Age field is empty.";
				}

				if (empty($email)) {
					$errors[] = "Email field is empty.";
				}

				if (!empty($errors)) {
					echo "<div class='message message-error'>";
					echo "<strong>Please fix the following:</strong><ul>";
					foreach ($errors as $error) {
						echo "<li>" . htmlspecialchars($error) . "</li>";
					}
					echo "</ul></div>";
					echo "<a class='btn btn-soft' href='javascript:self.history.back();'>Go Back</a>";
				} else {
					// Insert data into database
					$result = mysqli_query($mysqli, "INSERT INTO users (`name`, `age`, `email`) VALUES ('$name', '$age', '$email')");

					echo "<div class='message message-success'><strong>Data added successfully!</strong></div>";
					echo "<a class='btn btn-primary' href='index.php'>View Dashboard</a>";
				}
			} else {
				header("Location:add.php");
				exit;
			}
			?>
		</main>
	</div>
</body>
</html>
